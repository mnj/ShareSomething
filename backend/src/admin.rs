//! `sharesomething admin ...` commands for bootstrapping and recovering accounts.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, bail};
use clap::Subcommand;
use qrcode::{QrCode, render::unicode::Dense1x2};
use sqlx::SqlitePool;

use crate::{
    audit::{Action, Audit, Event},
    auth::{totp, users::hash_password},
    util::now,
};

#[derive(Subcommand)]
pub enum AdminCmd {
    /// Create the first admin account (password + TOTP). In single mode this is the owner.
    Init {
        /// Team mode: the admin's email address (single mode: omit).
        #[arg(long)]
        email: Option<String>,
        /// Reset an existing first admin's password/TOTP/passkeys and log out its sessions.
        #[arg(long)]
        force: bool,
        /// Don't set up TOTP (not recommended).
        #[arg(long)]
        no_totp: bool,
    },
    /// Change a user's password and log out their sessions.
    SetPassword {
        /// Which user (default: the first admin / single-mode owner).
        #[arg(long)]
        email: Option<String>,
    },
    /// Generate a new TOTP secret (or remove it with --disable).
    ResetTotp {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        disable: bool,
    },
}

async fn user_id(db: &SqlitePool, email: Option<&str>) -> anyhow::Result<i64> {
    let row: Option<(i64,)> = match email {
        Some(e) => {
            sqlx::query_as("SELECT id FROM users WHERE email = ?")
                .bind(e.trim().to_ascii_lowercase())
                .fetch_optional(db)
                .await?
        }
        None => sqlx::query_as("SELECT id FROM users WHERE id = 1").fetch_optional(db).await?,
    };
    Ok(row.context("no such user; run `admin init` first")?.0)
}

pub async fn run(cmd: AdminCmd, db: &SqlitePool) -> anyhow::Result<()> {
    let audit = Audit::new(db.clone());
    let cli = |a: Action, id: i64| Event::new(a).system("cli").target("user", id.to_string(), None);
    match cmd {
        AdminCmd::Init { email, force, no_totp } => {
            let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE id = 1").fetch_optional(db).await?;
            if exists.is_some() && !force {
                bail!("an admin already exists; use --force to reset it");
            }
            let email = email.map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty());
            if let Some(e) = &email
                && !e.contains('@')
            {
                bail!("--email must be an email address");
            }
            let hash = hash_password(&read_password()?)?;
            let secret = if no_totp { None } else { Some(enroll_totp()?) };
            let name = email.as_deref().and_then(|e| e.split('@').next()).unwrap_or("Owner").to_string();
            sqlx::query(
                "INSERT INTO users (id, email, name, role, status, password_hash, totp_secret, created_at)
                 VALUES (1, ?, ?, 'admin', 'active', ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET email = excluded.email, name = excluded.name, role = 'admin', status = 'active',
                   password_hash = excluded.password_hash, totp_secret = excluded.totp_secret, totp_last_step = NULL",
            )
            .bind(&email)
            .bind(&name)
            .bind(hash)
            .bind(secret)
            .bind(now())
            .execute(db)
            .await?;
            sqlx::query("DELETE FROM user_sessions WHERE user_id = 1").execute(db).await?;
            sqlx::query("DELETE FROM user_passkeys WHERE user_id = 1").execute(db).await?;
            audit
                .record(
                    cli(
                        if exists.is_some() {
                            Action::UserUpdated
                        } else {
                            Action::UserCreated
                        },
                        1,
                    )
                    .detail("role", "admin")
                    .detail("reset", exists.is_some()),
                )
                .await?;
            println!("Admin account {}.", if exists.is_some() { "reset" } else { "created" });
        }
        AdminCmd::SetPassword { email } => {
            let id = user_id(db, email.as_deref()).await?;
            let hash = hash_password(&read_password()?)?;
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
                .bind(hash)
                .bind(id)
                .execute(db)
                .await?;
            sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
                .bind(id)
                .execute(db)
                .await?;
            audit.record(cli(Action::AuthPasswordChanged, id)).await?;
            println!("Password changed; sessions logged out.");
        }
        AdminCmd::ResetTotp { email, disable } => {
            let id = user_id(db, email.as_deref()).await?;
            let secret = if disable { None } else { Some(enroll_totp()?) };
            sqlx::query("UPDATE users SET totp_secret = ?, totp_last_step = NULL WHERE id = ?")
                .bind(&secret)
                .bind(id)
                .execute(db)
                .await?;
            sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
                .bind(id)
                .execute(db)
                .await?;
            audit
                .record(cli(
                    if disable {
                        Action::AuthTotpDisabled
                    } else {
                        Action::AuthTotpEnabled
                    },
                    id,
                ))
                .await?;
            println!("TOTP {}; sessions logged out.", if disable { "disabled" } else { "reset" });
        }
    }
    Ok(())
}

/// Reads the password from `SS_ADMIN_PASSWORD` or prompts twice.
fn read_password() -> anyhow::Result<String> {
    let pw = match std::env::var("SS_ADMIN_PASSWORD") {
        Ok(pw) => pw,
        Err(_) => {
            let a = rpassword::prompt_password("New password: ")?;
            let b = rpassword::prompt_password("Repeat password: ")?;
            if a != b {
                bail!("passwords don't match");
            }
            a
        }
    };
    if pw.chars().count() < 12 {
        bail!("password must be at least 12 characters");
    }
    Ok(pw)
}

/// Shows the QR code / secret and, when interactive, confirms a code before saving.
fn enroll_totp() -> anyhow::Result<String> {
    let secret = totp::new_secret();
    let url = totp::otpauth_url(&secret)?;
    let qr = QrCode::new(url.as_bytes())?.render::<Dense1x2>().quiet_zone(true).build();
    println!("\nScan with your authenticator app:\n\n{qr}\n\nOr enter the secret manually: {secret}\n");
    if std::io::stdin().is_terminal() {
        for _ in 0..3 {
            print!("Enter the 6-digit code to confirm: ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if totp::verify(&secret, &line, now())?.is_some() {
                return Ok(secret);
            }
            println!("That code didn't match, try again.");
        }
        bail!("TOTP confirmation failed; nothing was saved");
    }
    println!("(non-interactive: saving without confirmation)");
    Ok(secret)
}

//! `sharesomething admin ...` commands for bootstrapping the owner account.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, bail};
use clap::Subcommand;
use qrcode::{QrCode, render::unicode::Dense1x2};
use sqlx::SqlitePool;

use crate::{
    auth::{owner::hash_password, totp},
    util::now,
};

#[derive(Subcommand)]
pub enum AdminCmd {
    /// Create the owner account (password + TOTP).
    Init {
        /// Replace an existing owner and log out all sessions.
        #[arg(long)]
        force: bool,
        /// Don't set up TOTP (not recommended).
        #[arg(long)]
        no_totp: bool,
    },
    /// Change the owner password and log out all sessions.
    SetPassword,
    /// Generate a new TOTP secret (or remove it with --disable).
    ResetTotp {
        #[arg(long)]
        disable: bool,
    },
}

pub async fn run(cmd: AdminCmd, db: &SqlitePool) -> anyhow::Result<()> {
    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM owner WHERE id = 1").fetch_optional(db).await?;
    match cmd {
        AdminCmd::Init { force, no_totp } => {
            if exists.is_some() && !force {
                bail!("owner already exists; use --force to replace it");
            }
            let hash = hash_password(&read_password()?)?;
            let secret = if no_totp { None } else { Some(enroll_totp()?) };
            sqlx::query("DELETE FROM owner").execute(db).await?;
            sqlx::query("DELETE FROM owner_sessions").execute(db).await?;
            sqlx::query("INSERT INTO owner (id, password_hash, totp_secret, created_at) VALUES (1, ?, ?, ?)")
                .bind(hash)
                .bind(secret)
                .bind(now())
                .execute(db)
                .await?;
            println!("Owner account created.");
        }
        AdminCmd::SetPassword => {
            exists.context("no owner yet; run `admin init`")?;
            let hash = hash_password(&read_password()?)?;
            sqlx::query("UPDATE owner SET password_hash = ? WHERE id = 1")
                .bind(hash)
                .execute(db)
                .await?;
            sqlx::query("DELETE FROM owner_sessions").execute(db).await?;
            println!("Password changed; all sessions logged out.");
        }
        AdminCmd::ResetTotp { disable } => {
            exists.context("no owner yet; run `admin init`")?;
            let secret = if disable { None } else { Some(enroll_totp()?) };
            sqlx::query("UPDATE owner SET totp_secret = ?, totp_last_step = NULL WHERE id = 1")
                .bind(&secret)
                .execute(db)
                .await?;
            sqlx::query("DELETE FROM owner_sessions").execute(db).await?;
            println!("TOTP {}; all sessions logged out.", if disable { "disabled" } else { "reset" });
        }
    }
    Ok(())
}

/// Reads the password from `SS_ADMIN_PASSWORD` or prompts twice.
fn read_password() -> anyhow::Result<String> {
    let pw = match std::env::var("SS_ADMIN_PASSWORD") {
        Ok(pw) => pw,
        Err(_) => {
            let a = rpassword::prompt_password("New owner password: ")?;
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

//! Outgoing email for recipient one-time codes.

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};

use crate::config::{EmailConfig, EmailMode, SmtpTls};

#[derive(Clone)]
pub enum Mailer {
    Disabled,
    Log,
    Smtp {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        from: Mailbox,
    },
    /// Collects messages in memory (tests).
    #[cfg(test)]
    Capture(std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>),
}

impl Mailer {
    pub fn from_config(cfg: &EmailConfig) -> anyhow::Result<Self> {
        Ok(match cfg.mode {
            EmailMode::Disabled => Mailer::Disabled,
            EmailMode::Log => {
                tracing::warn!("email.mode = log: one-time codes are written to the log, not sent");
                Mailer::Log
            }
            EmailMode::Smtp => {
                let mut b = match cfg.smtp_tls {
                    SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?,
                    SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?,
                    SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host),
                };
                if let Some(port) = cfg.smtp_port {
                    b = b.port(port);
                }
                if let (Some(u), Some(p)) = (&cfg.smtp_username, &cfg.smtp_password) {
                    b = b.credentials(Credentials::new(u.clone(), p.clone()));
                }
                Mailer::Smtp {
                    transport: Box::new(b.build()),
                    from: cfg.from.parse()?,
                }
            }
        })
    }

    pub fn enabled(&self) -> bool {
        !matches!(self, Mailer::Disabled)
    }

    pub async fn send_code(&self, to: &str, code: &str, base_url: &str) -> anyhow::Result<()> {
        let subject = format!("Your ShareSomething code: {code}");
        let body = format!(
            "Your one-time code is:\n\n    {code}\n\nIt is valid for 10 minutes. Enter it on {base_url} to open the share.\n\n\
             If you didn't ask for this, you can ignore this email.\n"
        );
        match self {
            Mailer::Disabled => anyhow::bail!("email is disabled"),
            Mailer::Log => {
                tracing::info!(%to, %code, "email one-time code (email.mode = log)");
                Ok(())
            }
            Mailer::Smtp { transport, from } => {
                let msg = Message::builder()
                    .from(from.clone())
                    .to(to.parse()?)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body)?;
                transport.send(msg).await?;
                Ok(())
            }
            #[cfg(test)]
            Mailer::Capture(sent) => {
                sent.lock().unwrap().push((to.to_string(), body));
                Ok(())
            }
        }
    }
}

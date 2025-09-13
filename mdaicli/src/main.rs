use mdaicli::{audit, cache, config, errors, io, model, opts, providers};

mod helptext;
use clap::Parser;
use errors::{exit_with, ErrorKind};
use opts::{Cli, Commands, ListType, RemoveType};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", helptext::FULL_HELP);
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse();

    if let Err(e) = real_main(cli) {
        exit_with(e)
    } else {
        ExitCode::SUCCESS
    }
}

fn real_main(cli: Cli) -> Result<(), errors::AppError> {
    // Load configuration with precedence: flags > env > file > defaults
    let mut cfg = config::Config::load(cli.config.as_deref(), cli.profile.as_deref())?;

    // Apply env overrides
    cfg.apply_env_overrides();

    // Apply CLI overrides
    cfg.apply_cli_overrides(&cli);

    // Ensure directories
    io::ensure_dirs(&cfg)?;

    // Dispatch commands
    match cli.command {
        Commands::Query(q) => {
            // Enforce allowed roots for any file args
            let mut check_files = q.input_files.clone();
            if let Some(p) = &q.messages_file {
                check_files.push(p.clone());
            }
            if let Some(p) = &q.tools_file {
                check_files.push(p.clone());
            }
            io::enforce_allowed_roots(&cfg, &check_files)?;

            // Reject URIs in file args
            for p in &check_files {
                if io::looks_like_uri(p) {
                    return Err(errors::AppError::with_kind(
                        ErrorKind::FileAccess,
                        format!(
                            "Rejected URI in --input-file: '{}'. Use MCP resource tools instead.",
                            p
                        ),
                    ));
                }
            }

            // Build request model
            let stdin_piped = atty::isnt(atty::Stream::Stdin);
            let req = model::build_request_from_query(&cfg, &q, stdin_piped)?;

            // Dry run: print request JSON and return
            if cli.dry_run {
                println!("{}", serde_json::to_string_pretty(&req)?);
                return Ok(());
            }

            let account = cli.account.clone().unwrap_or_else(|| "default".into());
            providers::run_query(&cfg, &account, &q)?;
        }
        Commands::Store(s) => {
            // Read secret from stdin or interactive prompt
            let secret = io::read_secret_from_stdin_or_tty(s.no_interactive)?;
            let account = s.account.clone().unwrap_or_else(|| "default".into());
            io::store_secret(
                &cfg,
                &s.provider,
                &account,
                &secret,
                s.base_url.clone(),
                s.org_id.clone(),
            )?;
            println!(
                "Stored credentials for provider '{}' (account '{}')",
                s.provider, account
            );
        }
        Commands::List(l) => match l.which {
            ListType::Providers => {
                // Static provider list for now
                println!("openai\nanthropic\nopenrouter");
            }
            ListType::Models { provider, refresh } => {
                let p = provider.unwrap_or_else(|| cfg.default.provider.clone());
                providers::list_models(&cfg, &p, refresh)?;
            }
            ListType::Credentials { verbose: _ } => {
                io::list_credentials()?;
            }
            ListType::Cache {
                provider,
                verbose: _,
            } => {
                cache::list_cache(&cfg, provider.as_deref())?;
            }
        },
        Commands::Remove(r) => match r.which {
            RemoveType::Credential {
                provider,
                account,
                all,
            } => {
                if all {
                    io::remove_all_credentials()?;
                    println!("Removed all stored credentials");
                } else {
                    let acc = account.unwrap_or_else(|| "default".into());
                    io::remove_credential(&provider, &acc)?;
                    println!("Removed credentials for '{}' (account '{}')", provider, acc);
                }
            }
            RemoveType::Cache {
                provider,
                older_than_days,
                all,
                confirm: _,
            } => {
                cache::remove_cache(&cfg, provider.as_deref(), older_than_days, all)?;
            }
        },
        Commands::Usage(u) => {
            let summary =
                crate::audit::summarize(&cfg, u.provider.as_deref(), u.account.as_deref(), u.days)?;
            match u.format.as_deref() {
                Some("csv") => {
                    let s = summary["summary"].clone();
                    println!("requests,total_tokens");
                    println!(
                        "{},{}",
                        s["requests"].as_u64().unwrap_or(0),
                        s["total_tokens"].as_u64().unwrap_or(0)
                    );
                }
                Some("table") | None => {
                    println!(
                        "Requests: {}",
                        summary["summary"]["requests"].as_u64().unwrap_or(0)
                    );
                    println!(
                        "Total tokens: {}",
                        summary["summary"]["total_tokens"].as_u64().unwrap_or(0)
                    );
                }
                Some("json") => {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
                Some(_) => {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
            }
        }
        Commands::Config(c) => {
            cfg.handle_config_command(c)?;
        }
        Commands::Openai(oc) => {
            match oc.which {
                opts::OpenaiWhich::Assistant { sub } => match sub {
                    opts::AssistantSub::List => providers::openai_list_assistants(
                        &cfg,
                        cli.account.as_deref().unwrap_or("default"),
                    )?,
                },
                opts::OpenaiWhich::VectorStore { sub } => match sub {
                    opts::VectorStoreSub::List => providers::openai_list_vector_stores(
                        &cfg,
                        cli.account.as_deref().unwrap_or("default"),
                    )?,
                    opts::VectorStoreSub::Create {
                        name,
                        files,
                        expires_days,
                    } => {
                        // enforce allowed roots if present
                        io::enforce_allowed_roots(&cfg, &files)?;
                        providers::openai_vector_store_create(
                            &cfg,
                            cli.account.as_deref().unwrap_or("default"),
                            &name,
                            &files,
                            expires_days,
                        )?;
                    }
                    opts::VectorStoreSub::Upload { store_id, files } => {
                        io::enforce_allowed_roots(&cfg, &files)?;
                        providers::openai_vector_store_upload(
                            &cfg,
                            cli.account.as_deref().unwrap_or("default"),
                            &store_id,
                            &files,
                        )?;
                    }
                    opts::VectorStoreSub::Delete { store_id } => {
                        providers::openai_vector_store_delete(
                            &cfg,
                            cli.account.as_deref().unwrap_or("default"),
                            &store_id,
                        )?;
                    }
                },
            }
        }
    }

    Ok(())
}

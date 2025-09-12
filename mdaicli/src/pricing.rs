use serde_json::json;

#[derive(Clone, Copy)]
struct Price {
    input_per_1k: f64,
    output_per_1k: f64,
    currency: &'static str,
    price_date: &'static str,
}

fn price_for(provider: &str, model: &str) -> Option<Price> {
    match provider {
        "openai" => {
            if model.starts_with("gpt-4o") {
                // Approx: $0.005 / $0.015 per 1k tokens (2024-05)
                Some(Price {
                    input_per_1k: 0.005,
                    output_per_1k: 0.015,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else if model.starts_with("gpt-4-turbo") || model.starts_with("gpt-4.1") {
                // Approx: $0.01 / $0.03 per 1k (2024-01)
                Some(Price {
                    input_per_1k: 0.010,
                    output_per_1k: 0.030,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else if model.starts_with("gpt-4") {
                // GPT-4 8k baseline: $0.03 / $0.06 per 1k (historic)
                Some(Price {
                    input_per_1k: 0.030,
                    output_per_1k: 0.060,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else if model.starts_with("gpt-3.5-turbo") || model.starts_with("gpt-3.5") {
                // Approx: $0.0005 / $0.0015 per 1k
                Some(Price {
                    input_per_1k: 0.0005,
                    output_per_1k: 0.0015,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else {
                None
            }
        }
        "anthropic" => {
            if model.contains("opus") {
                // Claude 3 Opus
                Some(Price {
                    input_per_1k: 0.015,
                    output_per_1k: 0.075,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else if model.contains("sonnet") {
                Some(Price {
                    input_per_1k: 0.003,
                    output_per_1k: 0.015,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else if model.contains("haiku") {
                Some(Price {
                    input_per_1k: 0.00025,
                    output_per_1k: 0.00125,
                    currency: "USD",
                    price_date: "2024-06-01",
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn estimate_cost(
    provider: &str,
    model: &str,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
) -> Option<serde_json::Value> {
    let price = price_for(provider, model)?;
    let pt = prompt_tokens.unwrap_or(0) as f64;
    let ct = completion_tokens.unwrap_or(0) as f64;
    let amount = (pt / 1000.0) * price.input_per_1k + (ct / 1000.0) * price.output_per_1k;
    Some(json!({
        "amount": (amount * 100000.0).round() / 100000.0, // 5dp rounding
        "currency": price.currency,
        "price_date": price.price_date
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_gpt4_estimation() {
        let est = estimate_cost("openai", "gpt-4", Some(1000), Some(1000)).unwrap();
        assert_eq!(est["currency"], "USD");
        let amt = est["amount"].as_f64().unwrap();
        assert!(amt > 0.05 && amt < 0.2);
    }

    #[test]
    fn anthropic_sonnet_estimation() {
        let est = estimate_cost(
            "anthropic",
            "claude-3-sonnet-20240229",
            Some(2000),
            Some(500),
        )
        .unwrap();
        let amt = est["amount"].as_f64().unwrap();
        assert!(amt > 0.0);
    }
}

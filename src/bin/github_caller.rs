use serde::Deserialize;
use std::error::Error;
use std::fs;
use regex::Regex;

use std::collections::HashMap;
use toml::Value as TomlValue;
use serde_json::{json, Value};
use reqwest::{Url, header, Client};


#[derive(Deserialize, Debug)]
struct PullRequest {
    title: String,
    html_url: String,
    // Add other fields as needed
}

async fn get_diff(url: Url, token: String) -> Result<String, Box<dyn Error>> {
    let client = Client::builder()
        .default_headers({
            let mut headers = header::HeaderMap::new();
            let insert = headers.insert(
                header::AUTHORIZATION, 
                format!("token {}", token.trim()).parse()?
            );
            headers
        })
        .build()?;

    let response = client.get(url).send().await?.text().await?;
    Ok(response)
}

fn diff_to_json(diff: &str) -> Value {
    let mut result = serde_json::Map::new();

    let mut current_file = String::new();
    let mut current_diff = String::new();
    let mut current_diff_json = serde_json::Map::new();
    let mut latest_key = String::new();
    // let mut latest_sub_key = String::new();
    for line in diff.lines() {
        if line.starts_with("diff --git") {
            if !current_file.is_empty() {
                result.insert(current_file.clone(), json!(current_diff.clone()));
                current_diff.clear();
            }
            let string_line = line.to_string();
            let parts: Vec<&str> = string_line.split_whitespace().collect();
            let b_path = parts[3];
            if b_path.starts_with("b/") {
                current_file = b_path[2..].to_string();
            } else {
                current_file = b_path.to_string();
            }
        } else {
            let string_line = line.to_string();
            let parts: Vec<&str> = string_line.split('\n').collect();
            for part in parts {
                if part.starts_with("+") {
                    let mini_part = part[1..].to_string();
                    if mini_part.starts_with("[[") {
                        let re = Regex::new(r"\[\[(.*?)\]\]").unwrap();
                        let new_key = re.captures(mini_part.as_str()).and_then(|cap| cap.get(1)).map(|m| m.as_str().to_string());
                        current_diff_json.insert(new_key.clone().unwrap(), json!(null));
                        latest_key = new_key.unwrap();
                    }
                    else if mini_part.starts_with("[") {
                            let re = Regex::new(r"\[(.*?)\]").unwrap();
                            let new_sub_key = re.captures(mini_part.as_str()).and_then(|cap| cap.get(1)).map(|m| m.as_str().to_string());
                            current_diff_json.insert(new_sub_key.clone().unwrap(), json!(null));
                            latest_key = new_sub_key.unwrap();
                    }
                    else {
                        let mini_parts: Vec<&str> = mini_part.split('=').collect();
                        if mini_parts.len() == 2 {
                            let key = mini_parts[0].replace(" ", "").replace("\\", "");
                            let value = mini_parts[1].replace(" ", "").replace("\\", "");
                            let new_json_value = json!({key: value});
                            current_diff_json.insert(latest_key.clone(), new_json_value);                        }
                    }
                    current_diff.push_str(part);
                    current_diff.push('\n');
                }
                    
                }
            }
            current_diff.push_str(line);
            current_diff.push('\n');
        }

    // Insert the last file diff
    if !current_file.is_empty() {
        let json_value: Value = Value::Object(current_diff_json);
        result.insert(current_file, json_value);
    }

    json!(result)
}


#[tokio::main]
async fn main() {
    let repo = "anoma/namada-testnets"; // Example: "owner/repository"
    let token_file = ".github_token.txt"; // Path to the file containing your GitHub token
    let token = fs::read_to_string(token_file).unwrap();
    let octocrab = octocrab::Octocrab::builder().personal_token(token).build().unwrap();
    let pulls = octocrab.pulls("anoma", "namada-testnets").list().per_page(1).send().await.unwrap();
    for pull in pulls {
        println!("Pull request number is {:?}", pull.number);
        println!("Title is {:?}", pull.title);
        println!("{:?}", pull.changed_files);
        let pull_req : PullRequest = PullRequest {
            title: pull.title.unwrap_or("".to_string()),
            html_url: pull.html_url.unwrap().to_string(),
        };
        
        if let Some(diff_url) = pull.diff_url {
            let temp_token = fs::read_to_string(token_file).unwrap();
            match get_diff(diff_url, temp_token).await {
                Ok(diff_text) => {
                    let json_diff = diff_to_json(&diff_text);
                    println!("JSON Diff: {:?}", json_diff);
                    }
                Err(e) => println!("Error: {}", e),
            }
        };
    }
}

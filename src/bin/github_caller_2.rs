use core::panic;
use namada_sdk::{eth_bridge::ethers::types::Transaction, tendermint::crypto::default::signature};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;

use reqwest::{header, Client, Url};
use serde_json::{json, Value};
use std::collections::HashMap;
use thiserror::Error;
use toml::Value as TomlValue;

#[derive(Deserialize, Debug)]
pub struct GitCommitResponse {
    pub sha: String,
    pub files: Vec<File>,
}

#[derive(Deserialize, Debug)]
pub struct File {
    pub filename: String,
    pub raw_url: String,
}

#[derive(Deserialize, Debug)]
pub struct TransactionsToml {
    pub established_account: Vec<EstablshedAccount>,
    pub validator_account: Vec<ValidatorAccount>,
    pub bond: Vec<Bond>,
}

#[derive(Deserialize, Debug)]
pub struct EstablshedAccount {
    pub vp: String,
    pub threshold: u8,
    pub public_keys: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ValidatorAccount {
    pub address: String,
    pub vp: String,
    pub commission_rate: String,
    pub max_commission_rate_change: String,
    pub net_address: String,
    pub consensus_key: ConsensusKey,
    pub protocol_key: ProtocolKey,
    pub tendermint_node_key: TendermintNodeKey,
    pub eth_hot_key: EthHotKey,
    pub eth_cold_key: EthColdKey,
    pub metadata: Metadata,
    pub signatures: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
pub struct ConsensusKey {
    pub pk: String,
    pub authorization: String,
}

#[derive(Deserialize, Debug)]
pub struct ProtocolKey {
    pub pk: String,
    pub authorization: String,
}

#[derive(Deserialize, Debug)]
pub struct TendermintNodeKey {
    pub pk: String,
    pub authorization: String,
}

#[derive(Deserialize, Debug)]
pub struct EthHotKey {
    pub pk: String,
    pub authorization: String,
}

#[derive(Deserialize, Debug)]
pub struct EthColdKey {
    pub pk: String,
    pub authorization: String,
}

#[derive(Deserialize, Debug)]
pub struct Metadata {
    pub email: String,
    pub discord: Option<String>,
    pub twitter: String,
    pub elements: String,
    pub discord_handle: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Bond {
    pub source: String,
    pub validator: String,
    pub amount: String,
    pub signatures: HashMap<String, String>,
}

impl TransactionsToml {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut validators = HashMap::new();
        for validator in &self.validator_account {
            let address = validator.address.clone();
            if validators.contains_key(&address) {
                return Err(ValidationError::InvalidValidatorAddress(address));
            }
            validators.insert(address, validator);
            validator.validate()?;
        }
        for bond in &self.bond {
            let source = bond.source.clone();
            let validator = bond.validator.clone();
            if !validators.contains_key(&source) {
                return Err(ValidationError::InvalidValidatorAddress(source));
            }
            if !validators.contains_key(&validator) {
                return Err(ValidationError::InvalidValidatorAddress(validator));
            }
        }
        Ok(())
    }
}

impl ValidatorAccount {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let vp = self.vp.clone();
        if vp != "vp_user" {
            return Err(ValidationError::InvalidVp(vp));
        }
        let commission_rate = self
            .commission_rate
            .parse::<f32>()
            .map_err(|e| ValidationError::InvalidCommissionRate(e.to_string()))?;
        if !(0_f32..=1_f32).contains(&commission_rate) {
            return Err(ValidationError::InvalidCommissionRate(
                commission_rate.to_string(),
            ));
        }
        let max_commission_rate_change = self
            .max_commission_rate_change
            .parse::<f32>()
            .map_err(|e| ValidationError::InvalidMaxCommissionRateChange(e.to_string()))?;
        if !(0_f32..=1_f32).contains(&max_commission_rate_change) {
            return Err(ValidationError::InvalidMaxCommissionRateChange(
                max_commission_rate_change.to_string(),
            ));
        }
        let nam_address = self.address.clone();
        let (tag, _, _) = bech32::decode(&nam_address)
            .map_err(|e| ValidationError::InvalidNamAddress(e.to_string()))?;
        if tag != "tnam" {
            return Err(ValidationError::InvalidNamAddress(nam_address));
        }

        let net_address = self.net_address.clone();
        if net_address.is_empty() {
            return Err(ValidationError::InvalidNetAddress(net_address));
        }

        if !self.consensus_key.validate() {
            return Err(ValidationError::InvalidConsensusKey(
                self.consensus_key.pk.clone(),
            ));
        }

        let email = self.metadata.email.clone();
        let re = Regex::new(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$").unwrap();
        if !re.is_match(&email) {
            return Err(ValidationError::InvalidEmail(email));
        }

        if !validate_signature(self.signatures.clone()) {
            return Err(ValidationError::InvalidSignatures(
                self.signatures.clone().values().next().unwrap().to_string(),
            ));
        }
        println!("Validator account successfully validated: {}", self.address);
        Ok(())
    }
}

pub fn validate_signature(signature: HashMap<String, String>) -> bool {
    let key = signature.keys().next().unwrap();
    let value = signature.values().next().unwrap();

    let (tag, _, _) = bech32::decode(key).unwrap();
    if tag != "tpknam" {
        return false;
    }

    let (tag, _, _) = bech32::decode(value).unwrap();
    if tag != "signam" {
        return false;
    }
    true
}

pub fn validate_validator_key(pk: String, authorization: String) -> bool {
    let (tag, _, _) = bech32::decode(&pk).unwrap();
    if tag != "tpknam" {
        return false;
    }

    let (tag, _, _) = bech32::decode(&authorization).unwrap();
    if tag != "signam" {
        return false;
    }
    true
}

impl ConsensusKey {
    pub fn validate(&self) -> bool {
        validate_validator_key(self.pk.clone(), self.authorization.clone())
    }
}

impl ProtocolKey {
    pub fn validate(&self) -> bool {
        validate_validator_key(self.pk.clone(), self.authorization.clone())
    }
}

impl TendermintNodeKey {
    pub fn validate(&self) -> bool {
        validate_validator_key(self.pk.clone(), self.authorization.clone())
    }
}

impl EthHotKey {
    pub fn validate(&self) -> bool {
        validate_validator_key(self.pk.clone(), self.authorization.clone())
    }
}

impl EthColdKey {
    pub fn validate(&self) -> bool {
        validate_validator_key(self.pk.clone(), self.authorization.clone())
    }
}

impl Bond {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let amount = self
            .amount
            .parse::<u64>()
            .map_err(|e| ValidationError::InvalidBondAmount(e.to_string()))?;
        if amount > 1000000 {
            return Err(ValidationError::InvalidBondAmount(
                amount.to_string(),
            ));
        }
        let signatures = self.signatures.clone();
        if !validate_signature(signatures) {
            return Err(ValidationError::InvalidSignatures(
                self.signatures.clone().values().next().unwrap().to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid vp: {0}")]
    InvalidVp(String),
    #[error("Invalid commission_rate: {0}")]
    InvalidCommissionRate(String),
    #[error("Invalid max_commission_rate_change: {0}")]
    InvalidMaxCommissionRateChange(String),
    #[error("Invalid nam_address: {0}")]
    InvalidNamAddress(String),
    #[error("Invalid net_address: {0}")]
    InvalidNetAddress(String),
    #[error("Invalid consensus_key: {0}")]
    InvalidConsensusKey(String),
    #[error("Invalid protocol_key: {0}")]
    InvalidProtocolKey(String),
    #[error("Invalid tendermint_node_key: {0}")]
    InvalidTendermintNodeKey(String),
    #[error("Invalid eth_hot_key: {0}")]
    InvalidEthHotKey(String),
    #[error("Invalid eth_cold_key: {0}")]
    InvalidEthColdKey(String),
    #[error("Invalid email: {0}")]
    InvalidEmail(String),
    #[error("Invalid signatures: {0}")]
    InvalidSignatures(String),
    #[error("Invalid validator address: {0}")]
    InvalidValidatorAddress(String),
    #[error("Invalid bond amount: {0}")]
    InvalidBondAmount(String),
    #[error("Invalid self bond")]
    InvalidSelfBond,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct StatusBody {
    pub state: String,
    pub description: String,
    pub context: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct LabelBody {
    pub labels: Vec<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct CommentBody {
    pub body: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PreviousValidator {
    pub missed_blocks : String,
    pub is_up : i8,
    pub stake : f32,
    pub merge : i8
}

pub type Validators = HashMap<String, PreviousValidator>;


// TODO: Check that it's the correct folder
// TODO: finish validating transactions.toml file

#[tokio::main]
async fn main() {
    
    let repo = "anoma/namada-testnets"; // Example: "owner/repository"
    let token_file = ".github_token.txt"; // Path to the file containing your GitHub token
    let token = fs::read_to_string(token_file).expect("Something went wrong reading the file");
    let octocrab = octocrab::Octocrab::builder().personal_token(token.clone()).build().unwrap();
    let pulls = octocrab.pulls("anoma", "namada-testnets").list().per_page(30).send().await.unwrap();
    let folder_name = "namada-public-testnet-15";
    let previous_validators: Validators = serde_json::from_str(&fs::read_to_string("src/artifacts/previous_validators.json").unwrap()).unwrap();
    let mut prs_to_look_at = vec![];
    let mut prs_to_close = vec![];
    let mut prs_to_probably_close = vec![];
    for pull in pulls {
        let token = fs::read_to_string(token_file).expect("Something went wrong reading the file");
        let pr_number = pull.number;
        let git_commit = pull.head.sha;
        let mut is_update = false;
        let mut is_merge = false;
        if let Some(pr_title) = pull.title {
            if !pr_title.contains("Update") {
                println!("not an update");
                continue
            } else {
                is_update = true;
            }
        }
        if !is_update {
            println!("is not update");
            continue
        }

        println!("Pull request number is {:?}", pr_number);
        println!("Git commit is {:?}", git_commit);

        let client = Client::new();
        let url = format!(
            "https://api.github.com/repos/{}/commits/{}",
            repo, git_commit
        );
        let response = client
            .get(&url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(header::USER_AGENT, "reqwest")
            .bearer_auth(token.clone())
            .send()
            .await
            .unwrap();
        let git_commit_response = response.json::<GitCommitResponse>().await.unwrap();
        let files = git_commit_response.files;
        if files.len() > 1 {
            println!("Too many files added, should close PR {}", pr_number);
            prs_to_close.push(pr_number);
            continue
        }
        let file_of_interest = files.get(0).unwrap();
        let raw_url = file_of_interest.raw_url.clone();
        let filename = file_of_interest.filename.clone();
        let alias = filename.replace(".toml", "").replace("namada-public-testnet-15/", "").to_lowercase();
        println!("Alias is {}", alias);
        // Check that there is no whitespace
        if alias.contains(" ") {
            println!("Whitespace in filename, should close pr {}", pr_number);
            continue
        }
        else {
            // Try to get alias from previous validators
            if let Some(previous_validator) = previous_validators.get(&alias) {
                println!("Found alias in previous validators!");
                if previous_validator.merge == 1 {
                    is_merge = true;
                }
            }
            else {
                println!("Did not find alias in previous validators, though said update");
                prs_to_probably_close.push(pr_number);
            }
        }
        // Check that it's the correct folder
        if !raw_url.contains(folder_name) {
            println!("Wrong folder, should close pr {}", pr_number);
            prs_to_close.push(pr_number);
            continue
        }


        let response = client
            .get(&raw_url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(header::USER_AGENT, "reqwest")
            .send()
            .await
            .unwrap();
        let toml_string = response.text().await.unwrap();

        let toml_value: TransactionsToml = toml::from_str(&toml_string).unwrap_or(TransactionsToml {
            established_account: vec![],
            validator_account: vec![],
            bond: vec![],
        });

        if toml_value.established_account.is_empty() {
            println!("Something went wrong when parsing {}", pr_number);
            prs_to_look_at.push(pr_number);
            continue
        };

        if let Err(_) = toml_value.validate() {
            // Make comment on pull request and close pr
            println!("Invalid toml file");
            let status_url = format!(
                "https://api.github.com/repos/anoma/namada-testnets/statuses/{}",
                git_commit
            );
            let status_body = StatusBody {
                state: "failure".to_string(),
                description: "Failed to validate transactions.toml file".to_string(),
                context: "namada-public-testnet-15".to_string(),
            };
            let response = client
                .post(&status_url)
                .json(&status_body)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(header::USER_AGENT, "reqwest")
                .bearer_auth(token.clone())
                .send()
                .await
                .unwrap();

                let label_url = format!("https://api.github.com/repos/anoma/namada-testnets/issues/{}/labels", pr_number);
                let label_body = LabelBody {
                    labels: vec!["invalid submission".to_string()],
                };
        
                let response = client
                    .post(&label_url)
                    .json(&label_body)
                    .header(header::ACCEPT, "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header(header::USER_AGENT, "reqwest")
                    .bearer_auth(token.clone())
                    .send()
                    .await
                    .unwrap();

                let comment_url = format!("https://api.github.com/repos/anoma/namada-testnets/issues/{}/comments", pr_number);
                let comment_text = format!("[{}](https://github.com/anoma/namada-testnets/pull/{}/commits/{})", git_commit[0..7].to_string(), pr_number, git_commit);
                let comment_body = CommentBody {
                    body: format!("The transactions.toml file for {} was deemed invalid", comment_text)
                };
        
                let response = client
                    .post(&comment_url)
                    .json(&comment_body)
                    .header(header::ACCEPT, "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header(header::USER_AGENT, "reqwest")
                    .bearer_auth(token)
                    .send()
                    .await
                    .unwrap();
        } else {
            println!("Valid toml file");
            let status_url = format!(
                "https://api.github.com/repos/anoma/namada-testnets/statuses/{}",
                git_commit
            );
            let status_body = StatusBody {
                state: "success".to_string(),
                description: "Successfully validated transactions.toml file".to_string(),
                context: "namada-public-testnet-15".to_string(),
            };
            let response = client
                .post(&status_url)
                .json(&status_body)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(header::USER_AGENT, "reqwest")
                .bearer_auth(token.clone())
                .send()
                .await
                .unwrap();

            let label_url = format!("https://api.github.com/repos/anoma/namada-testnets/issues/{}/labels", pr_number);
            let label_body = LabelBody {
                labels: vec!["valid submission".to_string()],
            };

            let response = client
                .post(&label_url)
                .json(&label_body)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(header::USER_AGENT, "reqwest")
                .bearer_auth(token.clone())
                .send()
                .await
                .unwrap();

            let comment_url = format!("https://api.github.com/repos/anoma/namada-testnets/issues/{}/comments", pr_number);
            let comment_text = format!("[{}](https://github.com/anoma/namada-testnets/pull/{}/commits/{})", git_commit[0..7].to_string(), pr_number, git_commit);
            let comment_body = CommentBody {
                body: format!("Successfully validated transactions.toml file for commit hash {}", comment_text)
            };

            let response = client
                .post(&comment_url)
                .json(&comment_body)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(header::USER_AGENT, "reqwest")
                .bearer_auth(token.clone())
                .send()
                .await
                .unwrap();

            if is_merge {
                println!("Attempting to merge PR {}", pr_number);
                let merge_url = format!("https://api.github.com/repos/anoma/namada-testnets/pulls/{}/merge", pr_number);
                let merge_body = json!({
                    "commit_title": format!("Merge pull request #{} for validator {}", pr_number, alias),
                    "commit_message": format!("Merge pull request #{} for validator {}", pr_number, alias),
                    "sha": git_commit,
                    "merge_method": "merge"
                });
                let response = client
                    .put(&merge_url)
                    .json(&merge_body)
                    .header(header::ACCEPT, "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header(header::USER_AGENT, "reqwest")
                    .bearer_auth(token)
                    .send()
                    .await
                    .unwrap();
            }
        }
    }
    println!("PRs to look at: {:?}", prs_to_look_at);
    println!("PRs to close: {:?}", prs_to_close);
    println!("PRs to probably close: {:?}", prs_to_probably_close);


}

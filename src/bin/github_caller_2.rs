use core::panic;
// use namada_sdk::{eth_bridge::ethers::types::Transaction, tendermint::crypto::default::signature};
use namada_apps::config::genesis::transactions::{
    SignedPk, SignedValidatorAccountTx, ValidatorAccountTx,
};
use namada_sdk::proof_of_stake::types::ValidatorMetaData;
use regex::Regex;
use serde::{Deserialize, Serialize};
// use std::{error::Error, collections::BTreeMap};
use std::fs;
use std::str::FromStr;

use reqwest::header;
use serde_json::json;
use std::collections::HashMap;
use std::collections::HashSet;
use thiserror::Error;

use namada_sdk::core::types::key::common::PublicKey;

// TODO: Allow also for bonds from anyone as long as it is TO a pilot-100

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

#[derive(Deserialize, Debug, Clone)]
pub struct ConsensusKey {
    pub pk: String,
    pub authorization: String,
}
impl From<ConsensusKey> for SignedPk {
    fn from(consensus_key: ConsensusKey) -> Self {
        let pk = consensus_key.pk;
        let authorization = consensus_key.authorization;
        SignedPk {
            pk: FromStr::from_str(&pk).unwrap(),
            authorization: FromStr::from_str(&authorization).unwrap(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProtocolKey {
    pub pk: String,
    pub authorization: String,
}
impl From<ProtocolKey> for SignedPk {
    fn from(protocol_key: ProtocolKey) -> Self {
        let pk = protocol_key.pk;
        let authorization = protocol_key.authorization;

        SignedPk {
            pk: FromStr::from_str(&pk).unwrap(),
            authorization: FromStr::from_str(&authorization).unwrap(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct TendermintNodeKey {
    pub pk: String,
    pub authorization: String,
}
impl From<TendermintNodeKey> for SignedPk {
    fn from(tendermint_node_key: TendermintNodeKey) -> Self {
        let pk = tendermint_node_key.pk;
        let authorization = tendermint_node_key.authorization;

        SignedPk {
            pk: FromStr::from_str(&pk).unwrap(),
            authorization: FromStr::from_str(&authorization).unwrap(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct EthHotKey {
    pub pk: String,
    pub authorization: String,
}
impl From<EthHotKey> for SignedPk {
    fn from(eth_hot_key: EthHotKey) -> Self {
        let pk = eth_hot_key.pk;
        let authorization = eth_hot_key.authorization;

        SignedPk {
            pk: FromStr::from_str(&pk).unwrap(),
            authorization: FromStr::from_str(&authorization).unwrap(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct EthColdKey {
    pub pk: String,
    pub authorization: String,
}
impl From<EthColdKey> for SignedPk {
    fn from(eth_cold_key: EthColdKey) -> Self {
        let pk = eth_cold_key.pk;
        let authorization = eth_cold_key.authorization;

        SignedPk {
            pk: FromStr::from_str(&pk).unwrap(),
            authorization: FromStr::from_str(&authorization).unwrap(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Metadata {
    pub email: String,
    #[serde(default)]
    pub discord: Option<String>,
    #[serde(default)]
    pub twitter: Option<String>,
    #[serde(default)]
    pub elements: Option<String>,
    #[serde(default)]
    pub discord_handle: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
}

impl Metadata {
    // Call this after to_email_metadata
    fn to_full_metadata(self) -> ValidatorMetaData {
        let email = self.email;
        let discord_handle = self.discord_handle.or(self.discord);
        if discord_handle.is_none() {
            println!("Discord handle is none for email {}", email);
        }
        let description = self.description;
        let website = self.website;
        let avatar = self.avatar;

        ValidatorMetaData {
            email,
            discord_handle,
            description,
            website,
            avatar,
        }
    }

    // Call this first
    fn to_email_metadata(&self) -> ValidatorMetaData {
        let email = self.email.clone();

        ValidatorMetaData {
            email,
            discord_handle: None,
            description: None,
            website: None,
            avatar: None,
        }
    }
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
        if self.validator_account.len() > 1 {
            return Err(ValidationError::InvalidValidatorAddress(
                "Too many validators added".to_string(),
            ));
        }
        let threshold = self.established_account[0].threshold;

        // Established account pk
        let ea_pk = self.established_account[0].public_keys[0].clone();
        let pilot_pks = read_file_to_set("src/artifacts/pilot_pks.txt").unwrap();
        if !pilot_pks.contains(&ea_pk) {
            return Err(ValidationError::InvalidValidatorAddress(
                "Established account is not a pilot".to_string(),
            ));
        }


        for validator in &self.validator_account {
            let full_signed_validator_tx: namada_apps::config::genesis::transactions::Signed<
                ValidatorAccountTx<SignedPk>,
            > = validator.from(true);
            if full_signed_validator_tx.verify_sig(threshold).is_err() {
                println!(
                    "Signature could not be verified for full metadata validator {}",
                    validator.address
                );
                let semi_signed_validator_tx = validator.from(false);
                if semi_signed_validator_tx.verify_sig(threshold).is_err() {
                    return Err(ValidationError::InvalidSignatures(
                        "Signatures could not be verified".to_string(),
                    ));
                }
            }
            println!(
                "Signature verified successfully for validator {}",
                validator.address
            );
            validator.validate()?;
        }

        for bond in &self.bond {
            bond.validate()?;
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

impl ValidatorAccount {
    fn from(&self, is_full: bool) -> SignedValidatorAccountTx {
        let nam_address =
            namada_sdk::core::types::address::Address::from_str(&self.address).unwrap();
        let nam_address = match nam_address {
            namada_sdk::core::types::address::Address::Established(account) => {
                namada_sdk::core::types::string_encoding::StringEncoded::new(account)
            }
            _ => panic!("Invalid address"),
        };
        let nam_commission_rate =
            namada_sdk::core::types::dec::Dec::from_str(&self.commission_rate).unwrap();
        let nam_max_commission_rate_change =
            namada_sdk::core::types::dec::Dec::from_str(&self.max_commission_rate_change).unwrap();

        let nam_metadata = match is_full {
            true => self.metadata.clone().to_full_metadata(),
            false => self.metadata.to_email_metadata(),
        };

        let validator_account_tx = ValidatorAccountTx {
            address: nam_address,
            vp: self.vp.clone(),
            commission_rate: nam_commission_rate,
            max_commission_rate_change: nam_max_commission_rate_change,
            net_address: FromStr::from_str(&self.net_address).unwrap(),
            consensus_key: self.consensus_key.clone().into(),
            protocol_key: self.protocol_key.clone().into(),
            tendermint_node_key: self.tendermint_node_key.clone().into(),
            eth_hot_key: self.eth_hot_key.clone().into(),
            eth_cold_key: self.eth_cold_key.clone().into(),
            metadata: nam_metadata,
        };

        let signed_validator_account_tx = SignedValidatorAccountTx {
            data: validator_account_tx,
            signatures: self
                .signatures
                .iter()
                .map(|(k, v)| (FromStr::from_str(k).unwrap(), FromStr::from_str(v).unwrap()))
                .collect(),
        };
        signed_validator_account_tx
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
        let pilot_pks = read_file_to_set("src/artifacts/pilot_pks.txt").unwrap();

        if self.source.starts_with("tpknam") {
            let source_pk = PublicKey::from_str(&self.source).unwrap();
            let source_address = namada_sdk::core::types::address::ImplicitAddress::from(&source_pk);
            println!("Source address is {:?}", source_address);
            if !pilot_pks.contains(&self.source) {
                return Err(ValidationError::NotAPilot100(
                    "Source is not a pilot".to_string(),
                ));
            }
        } else if self.source.starts_with("tnam") {
            let source_address = namada_sdk::core::types::address::Address::from_str(&self.source)
                .map_err(|e| ValidationError::InvalidValidatorAddress(e.to_string()))?;
            println!("Source address is {:?}", source_address);
        } else {
            return Err(ValidationError::InvalidValidatorAddress(
                "Source is not a namada address".to_string(),
            ));
        };
        
        
        let amount = self
            .amount
            .parse::<f64>()
            .map_err(|e| ValidationError::InvalidBondAmount(e.to_string()))?;
        if amount > 2631549.707602 {
            return Err(ValidationError::InvalidBondAmount(amount.to_string()));
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
    #[error("Not a pilot-100")]
    NotAPilot100(String),
}

#[derive(Deserialize, Debug, Serialize)]
pub struct StatusBody {
    pub state: String,
    pub description: String,
    pub context: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct PrUpdateBody {
    pub state: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct CommitBody {
    pub sha: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct Commits(pub Vec<CommitBody>);

#[derive(Deserialize, Debug, Serialize)]
pub struct LabelBody {
    pub labels: Vec<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct CommentBody {
    pub body: String,
}

// #[derive(Deserialize, Debug, Serialize)]
// pub struct PreviousValidator {
//     pub missed_blocks : String,
//     pub is_up : i8,
//     pub stake : f32,
//     pub merge : i8
// }

// pub type Validators = HashMap<String, PreviousValidator>;

// TODO: Check that it's the correct folder
// TODO: finish validating transactions.toml file

async fn comment_pull(pull_number: u32, comment: String, token: String) {
    println!("Attempting to comment on PR {}", pull_number);
    let client = reqwest::Client::new();
    let comment_url = format!(
        "https://api.github.com/repos/anoma/namada-shielded-expedition/issues/{}/comments",
        pull_number
    );
    let comment_body = CommentBody { body: comment };

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

    if response.status() != 201 {
        println!("Comment failed, got status code {}", response.status());
    }
}

async fn close_pull(pull_number: u32, token: String) {
    println!("Attempting to close PR {}", pull_number);
    let client = reqwest::Client::new();
    let pr_url = format!(
        "https://api.github.com/repos/anoma/namada-shielded-expedition/pulls/{}",
        pull_number
    );
    let pr_body = PrUpdateBody {
        state: "closed".to_string(),
    };
    let response = client
        .post(&pr_url)
        .json(&pr_body)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(header::USER_AGENT, "reqwest")
        .bearer_auth(token.clone())
        .send()
        .await
        .unwrap();

    if response.status() != 200 {
        println!("Closing PR failed, got status code {}", response.status());
    }
}

fn read_file_to_set(filename: &str) -> Result<HashSet<String>, std::io::Error> {
    let contents = fs::read_to_string(filename)?;
    let set: HashSet<String> = contents
        .split_whitespace()
        .map(|s| s.replace('\"', "").replace(",", "").replace(['[', ']'], ""))
        .collect();
    Ok(set)
}

#[tokio::main]
async fn main() {
    let repo = "anoma/namada-shielded-expedition"; // Example: "owner/repository"
    let token_file = ".github_token.txt"; // Path to the file containing your GitHub token
    let token = fs::read_to_string(token_file).expect("Something went wrong reading the file");
    let octocrab = octocrab::Octocrab::builder()
        .personal_token(token.clone())
        .build()
        .unwrap();
    let mut prs_to_look_at = vec![];
    let mut prs_to_close = vec![];
    let mut invalid_githubs = vec![];

    let folder_name = "signed_genesis_transactions";
    let pilot_githubs = read_file_to_set("src/artifacts/pilot_githubs.txt").unwrap();
    for page_number in 1..5 {
        let pulls = octocrab
            .pulls("anoma", "namada-shielded-expedition")
            .list()
            .per_page(100)
            .page(page_number as u32)
            .send()
            .await
            .unwrap();
        for pull in pulls {
            let token =
                fs::read_to_string(token_file).expect("Something went wrong reading the file");
            let pr_number = pull.number;
            // let git_commit = pull.head.sha;

            // let pr_body = pull.body.clone();
            let mut is_merge = false; // If the PR is a merge

            let client = reqwest::Client::new();
            let git_commits_url = format!(
                "https://api.github.com/repos/{}/pulls/{}/commits",
                repo, pr_number
            );

            let response = client
                .get(&git_commits_url)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(header::USER_AGENT, "reqwest")
                .bearer_auth(token.clone())
                .send()
                .await
                .unwrap();

            if response.status() != 200 {
                println!("Getting commits failed, got status code {}", response.status());
                continue;
            }

            let commits = response.json::<Commits>().await.unwrap();
            // Get the last commit
            let git_commit_body = commits.0.last().unwrap();
            let git_commit = git_commit_body.sha.clone();

            println!("Pull request number is {:?}", pr_number);
            println!("Git commit is {:?}", git_commit);

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
                println!("Files are: ");
                for file in &files {
                    print!("{}, ", file.filename);
                }
                comment_pull(
                    pr_number as u32,
                    format!("Too many files added, expected 1 found {}", files.len()),
                    token.clone(),
                )
                .await;
                close_pull(pr_number as u32, token.clone()).await;
                continue;
            }
            if files.is_empty() {
                println!("No files added, should close PR {}", pr_number);
                prs_to_close.push(pr_number);
                continue;
            }
            let file_of_interest = files.get(0).expect("Files found are empty");
            let raw_url = file_of_interest.raw_url.clone();
            let filename = file_of_interest.filename.clone();
            let alias = filename
                .replace(".toml", "")
                .replace(format!("{}/", folder_name).as_str(), "")
                .to_lowercase();
            let github_user = pull.user.unwrap().html_url.clone();

            println!("github user is {}", github_user);
            println!("Alias is {}", alias);
            // Check that there is no whitespace
            if filename.contains(" ") {
                println!("Whitespace in filename, should close pr {}", pr_number);
                comment_pull(
                    pr_number as u32,
                    format!("Whitespace found in filename. Found filename {}", filename),
                    token.clone(),
                )
                .await;
                close_pull(pr_number as u32, token.clone()).await;
                continue;
            } else {
                // Try to get alias from previous validators
                if pilot_githubs.contains(github_user.to_string().to_lowercase().as_str()) {
                    is_merge = true;
                } else {
                    println!("Not a pilot, should close pr {}", pr_number);
                    println!("Github user is {}", github_user);
                    invalid_githubs.push(pr_number);
                    comment_pull(
                    pr_number as u32,
                    format!("Github user {} is not a pilot-100", github_user),
                    token.clone(),
                    )
                    .await;
                    close_pull(pr_number as u32, token.clone()).await;
                    continue;
                }
            }
            // Check that it's the correct folder
            if !raw_url.contains(folder_name) {
                println!("Wrong folder, should close pr {}", pr_number);
                close_pull(pr_number as u32, token).await;
                continue;
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

            let toml_value: TransactionsToml = match toml::from_str(&toml_string) {
                Ok(toml_value) => toml_value,
                Err(e) => {
                    println!("Something went wrong when parsing {}", pr_number);
                    println!("Error: {}", e);
                    prs_to_look_at.push(pr_number);
                    continue;
                }
            };

            if toml_value.established_account.is_empty() {
                println!("Something went wrong when parsing {}", pr_number);
                prs_to_look_at.push(pr_number);
                continue;
            };

            if let Err(e) = toml_value.validate() {
                // Make comment on pull request and close pr
                println!("Invalid toml file");
                let status_url = format!(
                    "https://api.github.com/repos/anoma/namada-shielded-expedition/statuses/{}",
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

                let label_url = format!(
                    "https://api.github.com/repos/anoma/namada-shielded-expedition/issues/{}/labels",
                    pr_number
                );
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

                let comment_url = format!(
                    "https://api.github.com/repos/anoma/namada-shielded-expedition/issues/{}/comments",
                    pr_number
                );
                let comment_text = format!(
                    "[{}](https://github.com/anoma/namada-shielded-expedition/pull/{}/commits/{})",
                    git_commit[0..7].to_string(),
                    pr_number,
                    git_commit
                );
                let comment_body = CommentBody {
                    body: format!(
                        "The transactions.toml file for {} was deemed invalid with error {}",
                        comment_text, e
                    ),
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

                if let ValidationError::InvalidSignatures(_) = e {
                    close_pull(pr_number as u32, token).await;
                }
            } else {
                println!("Valid toml file");
                let status_url = format!(
                    "https://api.github.com/repos/anoma/namada-shielded-expedition/statuses/{}",
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

                let label_url = format!(
                    "https://api.github.com/repos/anoma/namada-shielded-expedition/issues/{}/labels",
                    pr_number
                );
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

                if is_merge {
                    let comment_url = format!(
                        "https://api.github.com/repos/anoma/namada-shielded-expedition/issues/{}/comments",
                        pr_number
                    );
                    let comment_text = format!(
                        "[{}](https://github.com/anoma/namada-shielded-expedition/pull/{}/commits/{})",
                        git_commit[0..7].to_string(),
                        pr_number,
                        git_commit
                    );

                    println!("Attempting to merge PR {}", pr_number);
                    let merge_url = format!(
                        "https://api.github.com/repos/anoma/namada-shielded-expedition/pulls/{}/merge",
                        pr_number
                    );
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
    }
    println!("PRs to look at: {:?}", prs_to_look_at);
    println!("PRs to close: {:?}", prs_to_close);
    println!("PRs with invalid_githubs: {:?}", invalid_githubs);
}

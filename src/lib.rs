use std::str::FromStr;
use thiserror::Error;

// Custom errors for Bitcoin operations
#[derive(Error, Debug)]
pub enum BitcoinError {
    #[error("Invalid transaction format")]
    InvalidTransaction,
    #[error("Invalid script format")]
    InvalidScript,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Parse error: {0}")]
    ParseError(String),
}

// Generic Point struct for Bitcoin addresses or coordinates
#[derive(Debug, Clone, PartialEq)]
pub struct Point<T> {
    pub x: T,
    pub y: T,
}

impl<T> Point<T> {
    /// Creates a new `Point` with the given x and y coordinates.
    pub fn new(x: T, y: T) -> Self {
        Point { x, y }
    }
}

// Custom serialization for Bitcoin transaction
pub trait BitcoinSerialize {
    /// Serializes the implementor into a vector of bytes.
    fn serialize(&self) -> Vec<u8>;
}

// Legacy Bitcoin transaction
#[derive(Debug, Clone)]
pub struct LegacyTransaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

impl LegacyTransaction {
    /// Returns a new `LegacyTransactionBuilder` for constructing a transaction.
    pub fn builder() -> LegacyTransactionBuilder {
        LegacyTransactionBuilder::new()
    }
}

// Transaction builder
pub struct LegacyTransactionBuilder {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

impl Default for LegacyTransactionBuilder {
    /// Provides default values for the `LegacyTransactionBuilder`.
    /// version: 1
    /// inputs: empty vector
    /// outputs: empty vector
    /// lock_time: 0
    fn default() -> Self {
        LegacyTransactionBuilder {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }
}

impl LegacyTransactionBuilder {
    /// Initializes a new builder by calling the default implementation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the transaction version.
    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    /// Adds an input to the transaction.
    pub fn add_input(mut self, input: TxInput) -> Self {
        self.inputs.push(input);
        self
    }

    /// Adds an output to the transaction.
    pub fn add_output(mut self, output: TxOutput) -> Self {
        self.outputs.push(output);
        self
    }

    /// Sets the lock_time for the transaction.
    pub fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Builds and returns the final `LegacyTransaction` from the builder's state.
    pub fn build(self) -> LegacyTransaction {
        LegacyTransaction {
            version: self.version,
            inputs: self.inputs,
            outputs: self.outputs,
            lock_time: self.lock_time,
        }
    }
}

// Transaction components
#[derive(Debug, Clone)]
pub struct TxInput {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    pub value: u64, // in satoshis
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

// Simple CLI argument parser
pub fn parse_cli_args(args: &[String]) -> Result<CliCommand, BitcoinError> {
    if args.is_empty() {
        return Err(BitcoinError::ParseError("No command provided".to_string()));
    }

    match args[0].as_str() {
        "send" => {
            if args.len() != 3 {
                return Err(BitcoinError::ParseError(
                    "Usage: send <amount> <address>".to_string(),
                ));
            }
            let amount = args[1]
                .parse::<u64>()
                .map_err(|e| BitcoinError::ParseError(format!("Invalid amount: {}", e)))?;
            let address = args[2].clone();
            Ok(CliCommand::Send { amount, address })
        }
        "balance" => {
            if args.len() != 1 {
                return Err(BitcoinError::ParseError("Usage: balance".to_string()));
            }
            Ok(CliCommand::Balance)
        }
        _ => Err(BitcoinError::ParseError(format!(
            "Unknown command: {}",
            args[0]
        ))),
    }
}

pub enum CliCommand {
    Send { amount: u64, address: String },
    Balance,
}

// Decoding legacy transaction
impl TryFrom<&[u8]> for LegacyTransaction {
    type Error = BitcoinError;

    /// Attempts to parse binary data into a `LegacyTransaction`.
    /// This implementation simplifies the parsing for the exercise,
    /// only reading version, input count, output count, and lock_time.
    /// It initializes input/output vectors with the read capacity, but does not parse their content.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // Minimum length for version (4 bytes), inputs count (4 bytes),
        // outputs count (4 bytes), and lock_time (4 bytes).
        const MIN_LEN: usize = 16;
        if data.len() < MIN_LEN {
            return Err(BitcoinError::InvalidTransaction);
        }

        // Read version (i32) from the first 4 bytes
        let version_bytes: [u8; 4] = data[0..4]
            .try_into()
            .map_err(|_| BitcoinError::InvalidTransaction)?;
        let version = i32::from_le_bytes(version_bytes);
        let mut offset = 4;

        // Read inputs count (u32) from the next 4 bytes
        let inputs_count_bytes: [u8; 4] = data[offset..offset + 4]
            .try_into()
            .map_err(|_| BitcoinError::InvalidTransaction)?;
        let inputs_count = u32::from_le_bytes(inputs_count_bytes);
        offset += 4;

        // Read outputs count (u32) from the next 4 bytes
        let outputs_count_bytes: [u8; 4] = data[offset..offset + 4]
            .try_into()
            .map_err(|_| BitcoinError::InvalidTransaction)?;
        let outputs_count = u32::from_le_bytes(outputs_count_bytes);
        offset += 4;

        // Read lock_time (u32) from the final 4 bytes
        let lock_time_bytes: [u8; 4] = data[offset..offset + 4]
            .try_into()
            .map_err(|_| BitcoinError::InvalidTransaction)?;
        let lock_time = u32::from_le_bytes(lock_time_bytes);

        // Initialize inputs and outputs vectors with the parsed counts as capacity.
        // For this exercise, the actual input/output data is not parsed.
        let inputs = Vec::with_capacity(inputs_count as usize);
        let outputs = Vec::with_capacity(outputs_count as usize);

        Ok(LegacyTransaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

// Custom serialization for transaction
impl BitcoinSerialize for LegacyTransaction {
    /// Serializes the `LegacyTransaction` into a byte vector.
    /// For this exercise, it only serializes the version and lock_time.
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Extend with version bytes (little-endian)
        bytes.extend_from_slice(&self.version.to_le_bytes());
        // Extend with lock_time bytes (little-endian)
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
        bytes
    }
}

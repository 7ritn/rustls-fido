use std::{env, io};
use std::io::Write;
use anyhow::Result;

#[macro_export]
macro_rules! env_var_or_default {
    ($name:expr, $default:expr) => {
        std::env::var($name).unwrap_or_else(|_| $default.to_string())
    };
}

pub(crate) fn get_fido_device_pin() -> Result<String> {
    if let Ok(pin) = env::var("FIDO_DEVICE_PIN") {
        Ok(pin)
    } else {
        let mut input = String::new();
        print!("Enter FIDO device PIN: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
}
use std::{str::FromStr, time::Duration};

use thiserror::Error;
use tokio::process::Command;
use tokio::sync::Semaphore;

#[derive(Debug, Error)]
pub enum WifiChannelError {
  #[error("unsupported Wi-Fi channel or center frequency: {value}")]
  InvalidValue { value: u16 },

  #[error("could not parse Wi-Fi channel \"{input}\"")]
  ParseError { input: String },

  #[error("failed to run iw: {source}")]
  IwSpawn {
    #[from]
    source: std::io::Error,
  },

  #[error("iw returned non-zero status {status:?}: {stderr}")]
  IwFailed { status: Option<i32>, stderr: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiChannel {
  number: u16,
  freq_mhz: u16,
}

impl WifiChannel {
  const fn const_new(number: u16, freq_mhz: u16) -> Self {
    Self { number, freq_mhz }
  }

  /// Channel number as understood by `iw` (e.g. 36).
  pub fn number(&self) -> u16 {
    self.number
  }

  /// Center frequency in MHz (e.g. 5180).
  pub fn freq_mhz(&self) -> u16 {
    self.freq_mhz
  }

  /// Construct from a channel number.
  pub fn from_channel_number(number: u16) -> Result<Self, WifiChannelError> {
    CHANNEL_TABLE
      .iter()
      .copied()
      .find(|entry| entry.number == number)
      .ok_or(WifiChannelError::InvalidValue { value: number })
  }

  /// Construct from a center frequency in MHz.
  pub fn from_freq_mhz(freq_mhz: u16) -> Result<Self, WifiChannelError> {
    CHANNEL_TABLE
      .iter()
      .copied()
      .find(|entry| entry.freq_mhz == freq_mhz)
      .ok_or(WifiChannelError::InvalidValue { value: freq_mhz })
  }

  /// Construct from either a channel number or a center frequency (both in MHz).
  fn new(value: u16) -> Result<Self, WifiChannelError> {
    Self::from_channel_number(value).or_else(|_| Self::from_freq_mhz(value))
  }
}

impl FromStr for WifiChannel {
  type Err = WifiChannelError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let trimmed = s.trim();
    let value: u16 = trimmed.parse().map_err(|_| WifiChannelError::ParseError {
      input: trimmed.to_string(),
    })?;
    Self::new(value)
  }
}

macro_rules! define_channels {
  ($(($name:ident, $number:expr, $freq:expr)),+ $(,)?) => {
    impl WifiChannel {
      $(pub const $name: WifiChannel = WifiChannel::const_new($number, $freq);)+
    }

    const CHANNEL_TABLE: &[WifiChannel] = &[
      $(WifiChannel::$name,)+
    ];
  };
}

define_channels!(
  // 2.4 GHz
  (WIFI_CHANNEL_1, 1, 2412),
  (WIFI_CHANNEL_2, 2, 2417),
  (WIFI_CHANNEL_3, 3, 2422),
  (WIFI_CHANNEL_4, 4, 2427),
  (WIFI_CHANNEL_5, 5, 2432),
  (WIFI_CHANNEL_6, 6, 2437),
  (WIFI_CHANNEL_7, 7, 2442),
  (WIFI_CHANNEL_8, 8, 2447),
  (WIFI_CHANNEL_9, 9, 2452),
  (WIFI_CHANNEL_10, 10, 2457),
  (WIFI_CHANNEL_11, 11, 2462),
  (WIFI_CHANNEL_12, 12, 2467),
  (WIFI_CHANNEL_13, 13, 2472),
  (WIFI_CHANNEL_14, 14, 2484),
  // 5 GHz (UNII)
  (WIFI_CHANNEL_36, 36, 5180),
  (WIFI_CHANNEL_38, 38, 5190),
  (WIFI_CHANNEL_40, 40, 5200),
  (WIFI_CHANNEL_42, 42, 5210),
  (WIFI_CHANNEL_44, 44, 5220),
  (WIFI_CHANNEL_46, 46, 5230),
  (WIFI_CHANNEL_48, 48, 5240),
  (WIFI_CHANNEL_52, 52, 5260),
  (WIFI_CHANNEL_56, 56, 5280),
  (WIFI_CHANNEL_60, 60, 5300),
  (WIFI_CHANNEL_64, 64, 5320),
  (WIFI_CHANNEL_100, 100, 5500),
  (WIFI_CHANNEL_104, 104, 5520),
  (WIFI_CHANNEL_108, 108, 5540),
  (WIFI_CHANNEL_112, 112, 5560),
  (WIFI_CHANNEL_116, 116, 5580),
  (WIFI_CHANNEL_120, 120, 5600),
  (WIFI_CHANNEL_124, 124, 5620),
  (WIFI_CHANNEL_128, 128, 5640),
  (WIFI_CHANNEL_132, 132, 5660),
  (WIFI_CHANNEL_136, 136, 5680),
  (WIFI_CHANNEL_140, 140, 5700),
  (WIFI_CHANNEL_144, 144, 5720),
  (WIFI_CHANNEL_149, 149, 5745),
  (WIFI_CHANNEL_153, 153, 5765),
  (WIFI_CHANNEL_157, 157, 5785),
  (WIFI_CHANNEL_161, 161, 5805),
  (WIFI_CHANNEL_165, 165, 5825),
);

const CHANNEL_LIST: [WifiChannel; 25] = [
  WifiChannel::WIFI_CHANNEL_36,
  WifiChannel::WIFI_CHANNEL_40,
  WifiChannel::WIFI_CHANNEL_44,
  WifiChannel::WIFI_CHANNEL_48,
  WifiChannel::WIFI_CHANNEL_52,
  WifiChannel::WIFI_CHANNEL_56,
  WifiChannel::WIFI_CHANNEL_60,
  WifiChannel::WIFI_CHANNEL_64,
  WifiChannel::WIFI_CHANNEL_100,
  WifiChannel::WIFI_CHANNEL_104,
  WifiChannel::WIFI_CHANNEL_108,
  WifiChannel::WIFI_CHANNEL_112,
  WifiChannel::WIFI_CHANNEL_116,
  WifiChannel::WIFI_CHANNEL_120,
  WifiChannel::WIFI_CHANNEL_124,
  WifiChannel::WIFI_CHANNEL_128,
  WifiChannel::WIFI_CHANNEL_132,
  WifiChannel::WIFI_CHANNEL_136,
  WifiChannel::WIFI_CHANNEL_140,
  WifiChannel::WIFI_CHANNEL_144,
  WifiChannel::WIFI_CHANNEL_149,
  WifiChannel::WIFI_CHANNEL_153,
  WifiChannel::WIFI_CHANNEL_157,
  WifiChannel::WIFI_CHANNEL_161,
  WifiChannel::WIFI_CHANNEL_165,
];

/// Set Wi-Fi channel by invoking `iw dev <dev> set channel <n>`.
pub async fn select_channel(dev: &str, wifi_channel: WifiChannel) -> Result<(), WifiChannelError> {
  run_iw_set_channel(dev, wifi_channel.number()).await
}

/// Cycle through the 5GHz channel list, issuing `iw dev <dev> set channel <n>`
/// once per second. Intended for simple background hopping while capturing.
pub async fn hop_channels(
  dev: &str,
  stop_signal: Option<&Semaphore>,
  interval: Duration,
) -> Result<(), WifiChannelError> {
  let mut idx = 0usize;
  loop {
    if stop_signal.is_some_and(|s| s.is_closed()) {
      return Ok(());
    }

    let channel = CHANNEL_LIST[idx];
    println!(
      "Scanning channel {} ({} MHz) [{}/{}]",
      channel.number(),
      channel.freq_mhz(),
      idx + 1,
      CHANNEL_LIST.len()
    );
    select_channel(dev, channel).await?;

    tokio::time::sleep(interval).await;
    idx = (idx + 1) % CHANNEL_LIST.len();
  }
}

async fn run_iw_set_channel(dev: &str, channel_number: u16) -> Result<(), WifiChannelError> {
  let channel_str = channel_number.to_string();
  let output = Command::new("iw")
    .args(["dev", dev, "set", "channel", &channel_str])
    .output()
    .await
    .map_err(|source| WifiChannelError::IwSpawn { source })?;

  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    return Err(WifiChannelError::IwFailed {
      status: output.status.code(),
      stderr,
    });
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn construct_from_channel_number() {
    let ch = WifiChannel::from_channel_number(36).expect("channel 36");
    assert_eq!(ch.number(), 36);
    assert_eq!(ch.freq_mhz(), 5180);
  }

  #[test]
  fn construct_from_frequency() {
    let ch = WifiChannel::from_freq_mhz(2412).expect("freq 2412");
    assert_eq!(ch.number(), 1);
  }

  #[test]
  fn parse_from_str() {
    let ch: WifiChannel = "44".parse().expect("parse 44");
    assert_eq!(ch.number(), 44);
  }

  #[test]
  fn reject_invalid_channel() {
    let err = WifiChannel::new(999).unwrap_err();
    assert!(matches!(err, WifiChannelError::InvalidValue { .. }));
  }
}

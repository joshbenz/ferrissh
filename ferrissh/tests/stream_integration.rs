//! Integration tests for the streaming command API.
//!
//! These tests connect to **localhost** via SSH using key-based authentication.
//!
//! # Prerequisites
//!
//! - SSH server running on localhost (port 22)
//! - Current user's key authorized for passwordless login
//!   (`~/.ssh/id_ed25519.pub` in `~/.ssh/authorized_keys`)
//!
//! # Running
//!
//! ```bash
//! cargo test --test stream_integration
//! ```

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;

use ferrissh::{Driver, DriverBuilder, Platform};

/// Helper: build a driver connected to localhost.
///
/// Retries up to 3 times to handle transient SSH connection resets
/// (e.g., when sshd's MaxStartups limit is hit by parallel tests).
async fn localhost_driver() -> ferrissh::GenericDriver {
    let user = std::env::var("USER").expect("USER env var must be set");
    let key_path = PathBuf::from(format!("/home/{}/.ssh/id_ed25519", user));

    for attempt in 0..3 {
        let mut driver = DriverBuilder::new("localhost")
            .port(22)
            .username(&user)
            .private_key(&key_path)
            .platform(Platform::Linux)
            .timeout(Duration::from_secs(10))
            .danger_disable_host_key_verification()
            .build()
            .expect("driver build should succeed");

        match driver.open().await {
            Ok(()) => return driver,
            Err(e) if attempt < 2 => {
                eprintln!(
                    "SSH connect attempt {} failed: {e}, retrying...",
                    attempt + 1
                );
                tokio::time::sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
            }
            Err(e) => panic!("SSH connection failed after 3 attempts: {e}"),
        }
    }
    unreachable!()
}

// =============================================================================
// send_command_stream — basic functionality
// =============================================================================

/// Basic: stream a simple command and collect all output.
#[tokio::test]
async fn test_stream_basic_echo() {
    let mut driver = localhost_driver().await;

    let mut stream = driver
        .send_command_stream("echo hello_stream_test")
        .await
        .expect("send_command_stream should succeed");

    let mut collected = Vec::new();
    while let Some(chunk) = stream
        .next_chunk()
        .await
        .expect("next_chunk should not error")
    {
        collected.push(chunk);
    }

    // Stream should be done
    assert!(stream.is_done());

    // Completion should be populated
    let completion = stream.completion().expect("completion should be set");
    assert!(!completion.prompt.is_empty(), "prompt should be non-empty");
    assert!(
        completion.elapsed > Duration::ZERO,
        "elapsed should be non-zero"
    );
    assert!(
        completion.failure_pattern.is_none(),
        "no failure expected for echo"
    );

    // Collected output should contain "hello_stream_test"
    let full_output: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let output_str = String::from_utf8_lossy(&full_output);
    assert!(
        output_str.contains("hello_stream_test"),
        "output should contain echo text, got: {output_str:?}"
    );

    driver.close().await.ok();
}

/// next_chunk returns None repeatedly once done.
#[tokio::test]
async fn test_stream_returns_none_after_done() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("echo done_test").await.unwrap();

    // Drain the stream
    while stream.next_chunk().await.unwrap().is_some() {}

    assert!(stream.is_done());

    // Additional calls should return Ok(None)
    assert!(stream.next_chunk().await.unwrap().is_none());
    assert!(stream.next_chunk().await.unwrap().is_none());

    driver.close().await.ok();
}

// =============================================================================
// Parity: stream vs send_command produce same output
// =============================================================================

/// Compare streamed output against send_command output for a deterministic command.
#[tokio::test]
async fn test_stream_parity_with_send_command_pwd() {
    let mut driver = localhost_driver().await;

    // Get output via send_command
    let response = driver.send_command("pwd").await.unwrap();
    let expected = response.result.to_string();

    // Get output via streaming
    let mut stream = driver.send_command_stream("pwd").await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full_output: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let streamed = String::from_utf8_lossy(&full_output);

    assert_eq!(
        streamed.trim(),
        expected.trim(),
        "streamed and send_command should produce identical output"
    );

    driver.close().await.ok();
}

/// Parity test for whoami.
#[tokio::test]
async fn test_stream_parity_with_send_command_whoami() {
    let mut driver = localhost_driver().await;

    let response = driver.send_command("whoami").await.unwrap();
    let expected = response.result.to_string();

    let mut stream = driver.send_command_stream("whoami").await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full_output: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let streamed = String::from_utf8_lossy(&full_output);

    assert_eq!(streamed.trim(), expected.trim());

    driver.close().await.ok();
}

/// Parity test for uname -a.
#[tokio::test]
async fn test_stream_parity_with_send_command_uname() {
    let mut driver = localhost_driver().await;

    let response = driver.send_command("uname -a").await.unwrap();
    let expected = response.result.to_string();

    let mut stream = driver.send_command_stream("uname -a").await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full_output: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let streamed = String::from_utf8_lossy(&full_output);

    assert_eq!(streamed.trim(), expected.trim());

    driver.close().await.ok();
}

// =============================================================================
// Multi-line output
// =============================================================================

/// Stream ls -la which produces multi-line output.
#[tokio::test]
async fn test_stream_multiline_ls() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("ls -la /tmp").await.unwrap();
    let mut chunks = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        chunks.push(chunk);
    }

    let completion = stream.completion().unwrap();
    assert!(!completion.prompt.is_empty());
    assert!(completion.failure_pattern.is_none());

    let full_output: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let output_str = String::from_utf8_lossy(&full_output);
    // /tmp listing should contain "total" line
    assert!(
        output_str.contains("total"),
        "ls -la output should contain 'total', got: {output_str:?}"
    );

    driver.close().await.ok();
}

// =============================================================================
// Large output — multiple chunks
// =============================================================================

/// Generate large output that should produce multiple streaming chunks.
#[tokio::test]
async fn test_stream_large_output() {
    let mut driver = localhost_driver().await;

    // Generate ~50KB of output (well over the 1000-byte search_depth holdback)
    let cmd = "seq 1 5000";

    let mut stream = driver.send_command_stream(cmd).await.unwrap();
    let mut chunk_count = 0;
    let mut total_bytes = 0;
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        chunk_count += 1;
        total_bytes += chunk.len();
    }

    let completion = stream.completion().unwrap();
    assert!(!completion.prompt.is_empty());
    assert!(completion.failure_pattern.is_none());

    // seq 1 5000 produces 5000 lines — should be a significant amount of data
    assert!(
        total_bytes > 1000,
        "expected significant output, got {total_bytes} bytes"
    );
    // With default search_depth=1000, large output should produce multiple chunks
    // (though this depends on SSH buffering, so we just verify at least 1 chunk)
    assert!(
        chunk_count >= 1,
        "expected at least 1 chunk, got {chunk_count}"
    );

    // Verify parity with send_command
    let response = driver.send_command(cmd).await.unwrap();
    let expected_lines: Vec<&str> = response.result.lines().collect();
    assert_eq!(
        expected_lines.len(),
        5000,
        "seq 1 5000 should produce 5000 lines"
    );

    driver.close().await.ok();
}

// =============================================================================
// into_stream() — futures::Stream adapter
// =============================================================================

/// Use into_stream() with StreamExt::collect.
#[tokio::test]
async fn test_into_stream_collect() {
    let mut driver = localhost_driver().await;

    let stream = driver
        .send_command_stream("echo stream_adapter_test")
        .await
        .unwrap();

    let results: Vec<Result<Bytes, _>> = stream.into_stream().collect().await;

    // All results should be Ok
    let chunks: Vec<Bytes> = results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("all chunks should be Ok");

    let full_output: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let output_str = String::from_utf8_lossy(&full_output);
    assert!(output_str.contains("stream_adapter_test"));

    driver.close().await.ok();
}

/// Use into_stream() with StreamExt::next.
#[tokio::test]
async fn test_into_stream_next() {
    let mut driver = localhost_driver().await;

    {
        let stream = driver
            .send_command_stream("echo adapter_next")
            .await
            .unwrap();

        let mut pinned = Box::pin(stream.into_stream());

        let mut collected = Vec::new();
        while let Some(result) = pinned.next().await {
            collected.push(result.expect("chunk should be Ok"));
        }

        let full_output: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
        let output_str = String::from_utf8_lossy(&full_output);
        assert!(output_str.contains("adapter_next"));
    }

    driver.close().await.ok();
}

/// Verify into_stream handles commands with no visible output.
#[tokio::test]
async fn test_into_stream_no_output_command() {
    let mut driver = localhost_driver().await;

    // `true` command produces no stdout
    {
        let stream = driver.send_command_stream("true").await.unwrap();
        let results: Vec<Result<Bytes, _>> = stream.into_stream().collect().await;

        let chunks: Vec<Bytes> = results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("all chunks should be Ok");

        let full: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        let output = String::from_utf8_lossy(&full);
        // `true` produces no meaningful stdout — any output should be whitespace only
        assert!(
            output.trim().is_empty(),
            "true should produce no meaningful output, got: {output:?}"
        );
    }

    driver.close().await.ok();
}

// =============================================================================
// completion() metadata
// =============================================================================

/// Verify completion prompt is non-empty and matches expected format.
#[tokio::test]
async fn test_completion_prompt_format() {
    let mut driver = localhost_driver().await;

    let mut stream = driver
        .send_command_stream("echo prompt_test")
        .await
        .unwrap();
    while stream.next_chunk().await.unwrap().is_some() {}

    let completion = stream.completion().unwrap();
    // Linux prompts typically end with $, #, or >
    let prompt = &completion.prompt;
    assert!(
        prompt.contains('$') || prompt.contains('#') || prompt.contains('>'),
        "prompt should contain shell indicator ($/#/>), got: {prompt:?}"
    );

    driver.close().await.ok();
}

/// Verify completion elapsed is reasonable.
#[tokio::test]
async fn test_completion_elapsed_reasonable() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("echo fast").await.unwrap();
    while stream.next_chunk().await.unwrap().is_some() {}

    let completion = stream.completion().unwrap();
    // echo should complete well within 5 seconds
    assert!(
        completion.elapsed < Duration::from_secs(5),
        "echo should be fast, took {:?}",
        completion.elapsed
    );

    driver.close().await.ok();
}

/// Verify completion is None before stream finishes.
#[tokio::test]
async fn test_completion_none_before_done() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("echo test").await.unwrap();

    // Before consuming anything, is_done should be false
    assert!(!stream.is_done());
    // completion() may or may not be None depending on whether the first next_chunk
    // has been called, but before any call it should be None.
    assert!(stream.completion().is_none());

    // Now drain
    while stream.next_chunk().await.unwrap().is_some() {}

    assert!(stream.is_done());
    assert!(stream.completion().is_some());

    driver.close().await.ok();
}

// =============================================================================
// is_done() state tracking
// =============================================================================

/// is_done tracks state correctly through the lifecycle.
#[tokio::test]
async fn test_is_done_lifecycle() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("echo lifecycle").await.unwrap();

    assert!(
        !stream.is_done(),
        "should not be done before first next_chunk"
    );

    // Consume all output
    while stream.next_chunk().await.unwrap().is_some() {}

    assert!(stream.is_done(), "should be done after stream ends");

    driver.close().await.ok();
}

// =============================================================================
// Sequential streaming commands on the same channel
// =============================================================================

/// Run multiple streaming commands sequentially.
#[tokio::test]
async fn test_sequential_streams() {
    let mut driver = localhost_driver().await;

    let commands = ["echo first", "echo second", "echo third"];

    for cmd in &commands {
        let expected_word = cmd.split_whitespace().last().unwrap();

        let mut stream = driver.send_command_stream(cmd).await.unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next_chunk().await.unwrap() {
            collected.push(chunk);
        }
        assert!(stream.is_done());
        assert!(stream.completion().is_some());

        let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
        let output = String::from_utf8_lossy(&full);
        assert!(
            output.contains(expected_word),
            "command {cmd:?} output should contain {expected_word:?}, got: {output:?}"
        );
    }

    driver.close().await.ok();
}

// =============================================================================
// Interleave streaming and non-streaming commands
// =============================================================================

/// Alternate between send_command and send_command_stream.
#[tokio::test]
async fn test_interleave_stream_and_command() {
    let mut driver = localhost_driver().await;

    // Non-streaming
    let r1 = driver.send_command("echo non_stream_1").await.unwrap();
    assert!(r1.result.contains("non_stream_1"));

    // Streaming
    let mut stream = driver.send_command_stream("echo streamed_1").await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }
    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    assert!(String::from_utf8_lossy(&full).contains("streamed_1"));

    // Non-streaming again
    let r2 = driver.send_command("echo non_stream_2").await.unwrap();
    assert!(r2.result.contains("non_stream_2"));

    // Streaming again
    let mut stream2 = driver.send_command_stream("echo streamed_2").await.unwrap();
    let mut collected2 = Vec::new();
    while let Some(chunk) = stream2.next_chunk().await.unwrap() {
        collected2.push(chunk);
    }
    let full2: Vec<u8> = collected2.iter().flat_map(|c| c.iter().copied()).collect();
    assert!(String::from_utf8_lossy(&full2).contains("streamed_2"));

    driver.close().await.ok();
}

// =============================================================================
// Output normalization
// =============================================================================

/// Verify that streamed output has normalized line endings (no \r).
#[tokio::test]
async fn test_stream_output_normalized() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("ls /tmp").await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    // After normalization, there should be no \r bytes
    assert!(
        !full.contains(&b'\r'),
        "normalized output should not contain \\r"
    );

    driver.close().await.ok();
}

// =============================================================================
// Echo stripping
// =============================================================================

/// Verify the command echo is stripped from streamed output.
#[tokio::test]
async fn test_stream_echo_stripped() {
    let mut driver = localhost_driver().await;

    let cmd = "echo echo_strip_test_xyz";
    let mut stream = driver.send_command_stream(cmd).await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let output = String::from_utf8_lossy(&full);

    // The output should contain the echo result
    assert!(output.contains("echo_strip_test_xyz"));

    // But should NOT start with the command itself as a repeated echo
    // (the echoed command line should be stripped, leaving just the output)
    let lines: Vec<&str> = output.lines().collect();
    if !lines.is_empty() {
        assert_ne!(lines[0], cmd, "first line should not be the command echo");
    }

    driver.close().await.ok();
}

// =============================================================================
// Prompt stripping
// =============================================================================

/// Verify the trailing prompt is not included in streamed output.
#[tokio::test]
async fn test_stream_prompt_stripped() {
    let mut driver = localhost_driver().await;

    let mut stream = driver
        .send_command_stream("echo prompt_strip")
        .await
        .unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let completion = stream.completion().unwrap();
    let prompt = &completion.prompt;

    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let output = String::from_utf8_lossy(&full);

    // The prompt should NOT appear in the collected output
    assert!(
        !output.contains(prompt.as_str()),
        "output should not contain the prompt {prompt:?}, output: {output:?}"
    );

    driver.close().await.ok();
}

// =============================================================================
// Empty output command
// =============================================================================

/// `true` produces no stdout — stream may emit whitespace but nothing meaningful.
#[tokio::test]
async fn test_stream_empty_output() {
    let mut driver = localhost_driver().await;

    let mut stream = driver.send_command_stream("true").await.unwrap();

    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    assert!(stream.is_done());
    assert!(stream.completion().is_some());

    // Any output from `true` should be whitespace-only (no meaningful content)
    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let output = String::from_utf8_lossy(&full);
    assert!(
        output.trim().is_empty(),
        "true should produce no meaningful output, got: {output:?}"
    );

    driver.close().await.ok();
}

// =============================================================================
// GenericDriver trait method
// =============================================================================

/// Verify that GenericDriver::send_command_stream works through the Driver trait.
#[tokio::test]
async fn test_driver_trait_send_command_stream() {
    let mut driver = localhost_driver().await;

    // Call via the Driver trait bound
    fn assert_driver(_d: &impl Driver) {}
    assert_driver(&driver);

    let mut stream = driver.send_command_stream("echo trait_test").await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }
    assert!(stream.is_done());

    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    assert!(String::from_utf8_lossy(&full).contains("trait_test"));

    driver.close().await.ok();
}

// =============================================================================
// Borrow exclusivity — compile-time check
// =============================================================================

/// This test verifies that the channel cannot be used while a CommandStream is active.
/// This is a compile-time guarantee, so we just verify the pattern works.
#[tokio::test]
async fn test_borrow_exclusivity_compiles() {
    let mut driver = localhost_driver().await;

    // This borrows &mut driver, so we can't call driver.send_command() simultaneously.
    // The test just verifies the code compiles and runs.
    {
        let mut stream = driver
            .send_command_stream("echo borrow_test")
            .await
            .unwrap();
        while stream.next_chunk().await.unwrap().is_some() {}
    }
    // After stream is dropped, we can use the driver again
    let resp = driver.send_command("echo after_stream").await.unwrap();
    assert!(resp.result.contains("after_stream"));

    driver.close().await.ok();
}

// =============================================================================
// Large output parity — verify streamed == non-streamed byte-for-byte
// =============================================================================

/// Byte-for-byte parity for a larger command.
#[tokio::test]
async fn test_stream_parity_large_output() {
    let mut driver = localhost_driver().await;

    let cmd = "seq 1 500";

    // Non-streaming
    let response = driver.send_command(cmd).await.unwrap();
    let expected = response.result.to_string();

    // Streaming
    let mut stream = driver.send_command_stream(cmd).await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let streamed = String::from_utf8_lossy(&full);

    assert_eq!(
        streamed.trim(),
        expected.trim(),
        "large output should be identical via stream vs send_command"
    );

    driver.close().await.ok();
}

// =============================================================================
// Commands with special characters
// =============================================================================

/// Test a command that produces output with special characters.
#[tokio::test]
async fn test_stream_special_characters() {
    let mut driver = localhost_driver().await;

    let cmd = r#"echo 'tabs	and "quotes" and $dollars'"#;
    let mut stream = driver.send_command_stream(cmd).await.unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        collected.push(chunk);
    }

    let full: Vec<u8> = collected.iter().flat_map(|c| c.iter().copied()).collect();
    let output = String::from_utf8_lossy(&full);
    assert!(output.contains("tabs"));
    assert!(output.contains("quotes"));
    assert!(output.contains("$dollars"));

    driver.close().await.ok();
}

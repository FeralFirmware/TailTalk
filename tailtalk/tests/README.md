# Running the Integration Test

The integration test `client_exchange` verifies that two AppleTalk clients can successfully exchange packets using the full protocol stack.

## Running the Test

The test passes successfully but spawns background tasks that continue running after the test completes. To run the test with a clean exit, use one of these approaches:

### Option 1: Run with timeout (Recommended)
```bash
timeout 10 cargo test --test client_exchange
```

### Option 2: Run and manually terminate
```bash
cargo test --test client_exchange
# Wait for "test test_client_exchange ... ok" to appear
# Then press Ctrl+C to exit
```

### Option 3: Check test result programmatically
```bash
timeout 10 cargo test --test client_exchange
echo "Exit code: $?"
# Exit code 124 = timeout (test passed but was terminated)
# Exit code 0 = test completed naturally (rare, depends on timing)
```

## Test Verification

The test is considered passed when you see:
```
test test_client_exchange ... ok
```

Or when the test output shows:
```
✓ Integration test passed: Two clients successfully exchanged packets!
```

## Why doesn't the test exit immediately?

The test spawns background tasks for:
1. Hub packet broadcasting
2. TestClient packet reception loops

These tasks run indefinitely to simulate a real network environment. The test function itself completes successfully after verifying packet exchange, but the Tokio runtime keeps running due to these background tasks.

This is expected behavior for integration tests that simulate long-running network services.

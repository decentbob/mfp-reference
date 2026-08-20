import { defineConfig } from "vitest/config";

// The suite is signature-bound: nearly every test signs and strictly verifies
// real Ed25519, and two of them do it a few hundred times — the 200-step
// conservation walk and §C3's "exactly one exit is open at every index" run
// about 2s each on a quiet machine.
//
// Against vitest's 5s default that is barely two-fold headroom, and those two
// are the only tests anywhere near it. A merge, an antivirus pass or a second
// test run alongside is enough to push one over, which shows up as a failure
// that does not reproduce — the worst kind, because it teaches you to re-run
// rather than to look.
//
// So the timeout is set well clear of anything the suite legitimately does. It
// is not a way to let a slow test pass: a test that needs 30s here has gone
// wrong, and the point of the margin is that exceeding it means something.
export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});

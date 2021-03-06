// Automatically fail after given time
TIMEOUT(10000, log.testFailed());

// When 'true' the whole output from motes is printed.
// Otherwise, only test summaries are logged.
var motes_output = false;

var failed = 0;
var succeeded = 0;

var done = 0;
var expected_done = 2;

while(true) {
    YIELD();

    if (motes_output)
        log.log(time + " " + "node-" + id + " "+ msg + "\n");

    if(msg.contains("[=check-me=]") == false)
        continue;

    if (!motes_output)
        log.log(msg.substring(12) + "\n")

    if(msg.contains("FAILED"))
        failed += 1;

    if(msg.contains("SUCCEEDED"))
        succeeded += 1;

    if(msg.contains("DONE"))
        done += 1;

    if (done == expected_done)
        break;
}

log.log("\nFINISHED RUNNING " + (failed+succeeded) + " TEST CASES\n");
log.log("Fails: " + failed + ", Successes: " + succeeded + "\n");

if(failed > 0)
    log.testFailed();

log.testOK();

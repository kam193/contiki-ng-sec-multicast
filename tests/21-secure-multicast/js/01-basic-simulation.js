// Automatically fail after given time
TIMEOUT(400000, log.testFailed());

var receiver_net1 = [
  "Joined multicast group ff1e::89:abcd",
  "Got RP cert",
  "Got: this_is_test",
  "Got: this_is_test",
];

var receiver_net2 = [
  "Joined multicast group ff1e::89:a00d",
  "Got RP cert",
  "Got: this_is_test",
  "Got: this_is_test",
];

var expected_mgs = {
  1: [
    "Sending message to ff1e::89:abcd",
    "Sending message to ff1e::89:a00d",
    "Sending message to ff1e::89:abcd",
    "Sending message to ff1e::89:a00d",
    "[DONE]",
  ],
  2: receiver_net1,
  3: receiver_net1,
  4: receiver_net2,
};
var last_msg = {
  1: 0,
  2: 0,
  3: 0,
  4: 0,
};

function check_expected() {
  if (msg.contains(expected_mgs[id][last_msg[id]])) {
    last_msg[id] += 1;
    return;
  }

  log.log("Fail! Expected: " + expected_mgs[id][last_msg[id]] + "\n");
  log.testFailed();
}

function check_final() {
  for (var mote_id in expected_mgs) {
    if (!expected_mgs.hasOwnProperty(mote_id)) continue;
    if (last_msg[mote_id] < expected_mgs[mote_id].length) return;
  }

  // log.testOK();
  log.log("Finished\n");
  log.testFailed();
}

while (true) {
  YIELD();
  log.log("[" + id + "] " + msg + "\n");
  if (msg.contains("[CRITICAL]")) log.testFailed();

  if (msg.contains("[SIMULATION]") == false) continue;
  // log.log("[" + id + "] " + msg.substring(13) + "\n");
  check_expected();
  check_final();
}

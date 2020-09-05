// Automatically fail after given time
TIMEOUT(500000, log.testFailed());

var root = [
  "Root initialized",
];

var receiver = [
  "Joined multicast group ff1e::89:a00d",
  "Got: this_is_test",
]

var sender = [
  "Sending message to ff1e::89:a00d",
  "[DONE]"
];

var expected_mgs = {
  1: root,
  2: sender,
  3: receiver,
  4: receiver,
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

  log.testOK();
}

while (true) {
  YIELD();
  log.log("[" + id + "] " + msg + "\n");
  
  if (msg.contains("[CRITICAL]")) log.testFailed();

  if (msg.contains("[SIMULATION]") == false) continue;

  check_expected();
  check_final();
}

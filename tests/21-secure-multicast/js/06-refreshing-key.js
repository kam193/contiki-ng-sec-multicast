// Automatically fail after given time
TIMEOUT(400000, log.testFailed());

var root = [
  "Root initialized",
];

var receiver = [
  "Joined multicast group ff1e::89:a00d",
  "Got: this_is_test",
  "Got: test_after_refresh",
]

var receiver_2 = [
  "Joined multicast group ff1e::89:a00d",
  "Got: this_is_test",
  function () {
    return !msg.contains("test_after_refresh");
  },
  "Timeout",
]

var sender = [
  "Sending message to ff1e::89:a00d",
  "Sending message to ff1e::89:a00d",
  "[DONE]"
];

var expected_mgs = {
  1: root,
  2: sender,
  3: receiver,
  4: receiver_2,
};

var last_msg = {
  1: 0,
  2: 0,
  3: 0,
  4: 0,
};

function assert_contains() {
  return msg.contains(expected_mgs[id][last_msg[id]]);
}

function check_expected() {
  var test_function = assert_contains;

  if (expected_mgs[id][last_msg[id]] instanceof Function) {
    test_function = expected_mgs[id][last_msg[id]];
  }

  if (test_function()) {
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

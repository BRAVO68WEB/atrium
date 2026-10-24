async function until(pred) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (pred()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

async function settled(readCount, quietMs = 400) {
  let last = readCount();
  let stableSince = Date.now();
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const count = readCount();
    if (count !== last) {
      last = count;
      stableSince = Date.now();
    } else if (Date.now() - stableSince >= quietMs) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
}

module.exports = { until, settled };

## 1. Fix scanner page reload loop

- [x] 1.1 Add `wasRunning` state variable to track scan running→stopped transitions
- [x] 1.2 Only trigger page reload when scan transitions from running to not-running (not every poll tick when `discovered_count > 0`)
- [x] 1.3 Set `wasRunning = true` when scan is detected as running or explicitly started

package agent.policy

contains_canary if {
  not disable_canary
  input.taint.contains_canary == true
}

package agent.policy

approval_required_for_tool if {
  data.data.settings.require_approval_for_tools[_] == input.tool
}

approval_required_for_retrieved_risk if {
  input.taint.from_retrieved == true
  data.data.settings.require_approval_when_from_retrieved_for_tool_risk[_] == input.risk.tool_risk
}

needs_approval if {
  not denied
  not disable_approvals
  approval_required_for_tool
}

needs_approval if {
  not denied
  not disable_approvals
  not disable_taint_approvals
  approval_required_for_retrieved_risk
}

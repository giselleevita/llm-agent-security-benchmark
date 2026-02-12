package agent.policy

is_tool_allowlisted if {
  data.data.tools.allowed[_] == input.tool
}

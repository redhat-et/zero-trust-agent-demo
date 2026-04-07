package demo.agents

import rego.v1

# Agent capability mappings
# Defines which document types/departments each agent can access
# These represent the MAXIMUM capabilities of the agent
# Actual access is further restricted by user permissions via intersection

agent_capabilities := {
    "summarizer-hr": ["hr", "engineering"],
    "zt-agent-summarizer-hr": ["hr", "engineering"],
    "summarizer-tech": ["finance", "engineering"],
    "reviewer-ops": ["engineering", "admin"],
    "reviewer-general": ["engineering", "finance", "admin", "hr"],
}

# Helper rule: Check if an agent has a specific capability
has_capability(agent_name, department) if {
    capability_list := agent_capabilities[agent_name]
    department in capability_list
}

# Helper rule: Get all capabilities for an agent
get_capabilities(agent_name) := capabilities if {
    capabilities := agent_capabilities[agent_name]
}

# Default: unknown agents have no capabilities
get_capabilities(agent_name) := [] if {
    not agent_capabilities[agent_name]
}

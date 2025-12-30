from thesis.agents.rule_agent import RuleAgent, WAZUH_RULE_SYSTEM_PROMPT
from thesis.llm.client import OllamaLlmClient


class WazuhRuleAgent(RuleAgent):
    def __init__(self, llm_client: OllamaLlmClient) -> None:
        super().__init__(llm_client, system_prompt=WAZUH_RULE_SYSTEM_PROMPT)

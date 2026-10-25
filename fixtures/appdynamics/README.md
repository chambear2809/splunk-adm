# AppDynamics Application Model XML fixtures

These synthetic XML files follow the XML shapes in the official [AppDynamics 26.10 Application Model API documentation](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.10.0/extend-splunk-appdynamics/splunk-appdynamics-apis/application-model-api). They contain no customer data or credentials.

The fixtures cover two applications with colliding tier/node IDs, IPv4 and IPv6, two nodes sharing one IPv4, a zone-scoped IPv6 address, and backend records with positive, zero and absent association IDs. Backend properties include credential-like values to verify sanitization and unresolved hostname candidates. The node XML uses the documented `ipAddresses/ipAddress` wrapping. The collector rejects unknown structures instead of coercing alternative JSON or XML encodings.

Tests load these files as data through a fake Controller transport. No fixture script is executed and no live Controller is contacted by tests.

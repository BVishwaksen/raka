# Neutral tool manifest
```yaml
tools:
  get_order_status:
    requires_auth: true
    trusted_params: [customer_id]            # must equal session.principal_id; host binds it, never the model
    validated_params: {order_id: "^ORD-[0-9]{6}$"}   # fullmatch; all listed params are required
    max_rows: 5
    approval: auto                           # auto | confirm | human_only
  send_email: {requires_auth: true, allowed_domains: [example.com], approval: confirm, side_effects: true}
```
Pass the **final** arguments (model-supplied plus host-injected) to the guard so it verifies what will actually run.
Optional keys: `enabled`, `side_effects`, `max_calls_per_minute`.

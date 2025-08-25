from app import create_app

app = create_app()

print("Registered routes:")
for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
    print(rule.rule)

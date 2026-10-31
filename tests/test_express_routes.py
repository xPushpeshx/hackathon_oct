from pathlib import Path

from engine.ast_express import discover_express_routes


def test_express_adapter_discovers_routes_and_inputs(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "server.js").write_text(
        """
const express = require("express");
const app = express();
const router = express.Router();

router.get("/search", (req, res) => {
  const q = req.query.q;
  res.json({ q });
});

router.post("/profile/:userId", (req, res) => {
  const userId = req.params.userId;
  const email = req.body.email;
  res.json({ userId, email });
});

app.use("/api", router);

app.get("/redirect", (req, res) => {
  const nextUrl = req.query.next;
  res.redirect(nextUrl);
});

module.exports = app;
""".strip(),
        encoding="utf-8",
    )

    routes = discover_express_routes(app_dir, "juice-shop")
    route_map = {route.path: route for route in routes}

    assert {"/api/search", "/api/profile/{param}", "/redirect"} <= set(route_map)
    assert route_map["/api/search"].methods == ["GET"]
    assert {item.name for item in route_map["/api/search"].inputs} == {"q"}
    assert {item.name for item in route_map["/api/profile/{param}"].inputs} == {"userId", "email"}

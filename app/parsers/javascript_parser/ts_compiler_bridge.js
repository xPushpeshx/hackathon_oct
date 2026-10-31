// app/parsers/javascript_parser/ts_compiler_bridge.js
/**
 * Uses the official TypeScript Compiler API (ts.createSourceFile) to extract:
 * 1. Imports / requires
 * 2. Functions, exported handlers, and Juice-Shop-style higher-order route factories
 * 3. Express router.use / app.use mounts and app.get/post/put/delete/patch routes
 * 4. Inside each function: req.query/body/params/headers accesses & 1-hop function calls
 */
const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const IGNORED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "frontend", "coverage", "test", "tests", "vagrant"
]);
const HTTP_METHODS = new Set(["get", "post", "put", "delete", "patch", "all"]);
const REQ_SOURCES = { query: "query", body: "body", params: "path", headers: "header", cookies: "cookie" };

function walkFiles(dir, rootDir, fileList = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, rootDir, fileList);
    } else if (/\.(ts|js)$/.test(entry.name) && !entry.name.endsWith(".d.ts") && !entry.name.endsWith(".spec.ts")) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

function getLine(sourceFile, pos) {
  return sourceFile.getLineAndCharacterOfPosition(pos).line + 1;
}

function getPathLiteral(arg) {
  if (!arg) return null;
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return arg.text;
  return null;
}

function getRoutePathFromCallExpression(node) {
  if (!ts.isCallExpression(node)) return null;
  const expr = node.expression;
  if (!ts.isPropertyAccessExpression(expr)) return null;

  const methodName = expr.name.text.toLowerCase();
  if (methodName === "route") {
    return getPathLiteral(node.arguments[0]);
  }

  if (ts.isCallExpression(expr.expression) && ts.isPropertyAccessExpression(expr.expression.expression)) {
    const baseMethod = expr.expression.expression.name.text.toLowerCase();
    if (baseMethod === "route") {
      return getPathLiteral(expr.expression.expression.arguments[0]);
    }
  }

  return null;
}

function analyzeFunctionBody(fnNode, sourceFile) {
  const params = [];
  const calls = [];
  const aliases = {}; // e.g., const query = req.query

  function visit(node) {
    // 1. Destructuring: const { q, id } = req.query / req.body / req.params
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isPropertyAccessExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === "req"
    ) {
      const reqProp = node.initializer.name.text;
      const sourceType = REQ_SOURCES[reqProp];
      if (sourceType) {
        if (ts.isObjectBindingPattern(node.name)) {
          for (const el of node.name.elements) {
            const pName = (el.propertyName || el.name).getText(sourceFile);
            params.push({ name: pName, source: sourceType, line: getLine(sourceFile, el.getStart(sourceFile)) });
          }
        } else if (ts.isIdentifier(node.name)) {
          aliases[node.name.text] = sourceType;
        }
      }
    }

    // 2. Direct property access: req.query.q, req.body.email, req.params.id
    if (ts.isPropertyAccessExpression(node)) {
      const expr = node.expression;
      if (
        ts.isPropertyAccessExpression(expr) &&
        ts.isIdentifier(expr.expression) &&
        expr.expression.text === "req"
      ) {
        const src = REQ_SOURCES[expr.name.text];
        if (src) {
          params.push({
            name: node.name.text,
            source: src,
            line: getLine(sourceFile, node.getStart(sourceFile)),
          });
        }
      } else if (ts.isIdentifier(expr) && aliases[expr.text]) {
        params.push({
          name: node.name.text,
          source: aliases[expr.text],
          line: getLine(sourceFile, node.getStart(sourceFile)),
        });
      }
    }

    // 3. Bracket access: req.query['q'], req.body['email'], req.headers['authorization']
    if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) {
      const keyName = node.argumentExpression.text;
      const expr = node.expression;
      if (
        ts.isPropertyAccessExpression(expr) &&
        ts.isIdentifier(expr.expression) &&
        expr.expression.text === "req"
      ) {
        const src = REQ_SOURCES[expr.name.text];
        if (src) {
          params.push({
            name: keyName,
            source: src,
            line: getLine(sourceFile, node.getStart(sourceFile)),
          });
        }
      }
    }

    // 4. Function calls inside handler body
    if (ts.isCallExpression(node)) {
      let calleeName = null;
      if (ts.isIdentifier(node.expression)) {
        calleeName = node.expression.text;
      } else if (ts.isPropertyAccessExpression(node.expression)) {
        calleeName = `${node.expression.expression.getText(sourceFile)}.${node.expression.name.text}`;
      }
      if (calleeName) {
        calls.push({
          callee: calleeName,
          line: getLine(sourceFile, node.getStart(sourceFile)),
        });
      }
    }

    ts.forEachChild(node, visit);
  }

  if (fnNode.body) {
    visit(fnNode.body);
  }
  return { params, calls };
}

function parseFile(filePath, rootDir) {
  const relPath = path.relative(rootDir, filePath).split(path.sep).join("/");
  const content = fs.readFileSync(filePath, "utf8");
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);

  const imports = {};     // localName -> { from: "./routes/search", imported: "default" | symbol }
  const functions = {};   // fnName -> { name, start_line, end_line, params, calls, is_default_export }
  const mounts = [];      // { parent_router, prefix, target_router, line }
  const routes = [];      // { router, method, path, handler_ref, middlewares, inline_handler, line }

  function registerFunction(name, fnNode, isDefaultExport = false) {
    const start_line = getLine(sourceFile, fnNode.getStart(sourceFile));
    const end_line = getLine(sourceFile, fnNode.getEnd());
    const { params, calls } = analyzeFunctionBody(fnNode, sourceFile);
    functions[name] = { name, start_line, end_line, params, calls, is_default_export: isDefaultExport };
  }

  function visit(node) {
    // A. ES Imports
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const modPath = node.moduleSpecifier.text;
      if (node.importClause) {
        if (node.importClause.name) {
          imports[node.importClause.name.text] = { from: modPath, imported: "default" };
        }
        if (node.importClause.namedBindings) {
          const bindings = node.importClause.namedBindings;
          if (ts.isNamespaceImport(bindings)) {
            imports[bindings.name.text] = { from: modPath, imported: "default" };
          } else if (ts.isNamedImports(bindings)) {
            for (const el of bindings.elements) {
              const local = el.name.text;
              const orig = el.propertyName ? el.propertyName.text : local;
              imports[local] = { from: modPath, imported: orig };
            }
          }
        }
      }
    }

    // B. TypeScript import = require(): import search = require('./routes/search')
    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression)
    ) {
      imports[node.name.text] = { from: node.moduleReference.expression.text, imported: "default" };
    }

    // C. CommonJS require: const search = require('./routes/search')
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isCallExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === "require" &&
      node.initializer.arguments.length === 1 &&
      ts.isStringLiteral(node.initializer.arguments[0])
    ) {
      const modPath = node.initializer.arguments[0].text;
      if (ts.isIdentifier(node.name)) {
        imports[node.name.text] = { from: modPath, imported: "default" };
      } else if (ts.isObjectBindingPattern(node.name)) {
        for (const el of node.name.elements) {
          const local = el.name.getText(sourceFile);
          const orig = el.propertyName ? el.propertyName.getText(sourceFile) : local;
          imports[local] = { from: modPath, imported: orig };
        }
      }
    }

    // D. Named Function Declarations
    if (ts.isFunctionDeclaration(node) && node.name) {
      const isExportDefault =
        node.modifiers && node.modifiers.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword);
      registerFunction(node.name.text, node, Boolean(isExportDefault));
    }

    // E. Arrow / Function Expressions assigned to variables
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      registerFunction(node.name.text, node.initializer, false);
    }

    // F. module.exports = function searchProducts() {} or exports.login = (req, res) => {}
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const leftText = node.left.getText(sourceFile);
      const right = node.right;
      if (leftText === "module.exports" || leftText === "exports") {
        if (ts.isFunctionExpression(right) || ts.isArrowFunction(right)) {
          const fnName = right.name ? right.name.text : path.basename(filePath, path.extname(filePath));
          registerFunction(fnName, right, true);
        } else if (ts.isIdentifier(right) && functions[right.text]) {
          functions[right.text].is_default_export = true;
        }
      } else if (leftText.startsWith("module.exports.") || leftText.startsWith("exports.")) {
        const exportedProp = leftText.split(".").pop();
        if (ts.isFunctionExpression(right) || ts.isArrowFunction(right)) {
          registerFunction(exportedProp, right, false);
        }
      }
    }

    // G. Express Route & Router Calls
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const methodOrUse = node.expression.name.text.toLowerCase();
      const receiver = node.expression.expression;
      const routerName = ts.isIdentifier(receiver) ? receiver.text : "app";

      // Case 1: app.use('/api/orders', orderRouter)
      if (methodOrUse === "use" && node.arguments.length >= 2) {
        const firstArg = node.arguments[0];
        const lastArg = node.arguments[node.arguments.length - 1];
        const targetName = ts.isIdentifier(lastArg)
          ? lastArg.text
          : ts.isCallExpression(lastArg) && ts.isIdentifier(lastArg.expression)
          ? lastArg.expression.text
          : null;
        if (targetName) {
          mounts.push({
            parent_router: routerName,
            prefix: ts.isStringLiteral(firstArg) ? firstArg.text : null,
            target_router: targetName,
            resolved: ts.isStringLiteral(firstArg),
            line: getLine(sourceFile, node.getStart(sourceFile)),
          });
        }
      }

      // Case 2: router.route('/users/:id').get(handler) or app.route('/users/:id').post(handler)
      let routePath = null;
      let routeRouterName = routerName;

      if (ts.isCallExpression(receiver) && ts.isPropertyAccessExpression(receiver.expression)) {
        const nestedMethod = receiver.expression.name.text.toLowerCase();
        if (nestedMethod === "route") {
          routePath = getRoutePathFromCallExpression(receiver);
          if (routePath) {
            routeRouterName = ts.isIdentifier(receiver.expression.expression)
              ? receiver.expression.expression.text
              : routerName;
          }
        }
      }

      const effectiveRoutePath = routePath || getPathLiteral(node.arguments[0]);
      const maybeHttpMethod = routePath ? methodOrUse : null;

      // Case 3: app.get('/rest/products/search', middleware, handler)
      if (HTTP_METHODS.has(methodOrUse) && node.arguments.length >= 2) {
        const firstArg = node.arguments[0];
        const routePathValue = getPathLiteral(firstArg);
        if (routePathValue) {
          const handlerArg = node.arguments[node.arguments.length - 1];
          const middlewareArgs = node.arguments.slice(1, -1);
          const middlewares = middlewareArgs.map((m) => m.getText(sourceFile));

          let handlerRef = null;
          let inlineHandler = null;

          if (ts.isArrowFunction(handlerArg) || ts.isFunctionExpression(handlerArg)) {
            const inlineName = `inline_${methodOrUse}_${getLine(sourceFile, handlerArg.getStart(sourceFile))}`;
            const { params, calls } = analyzeFunctionBody(handlerArg, sourceFile);
            inlineHandler = {
              name: inlineName,
              start_line: getLine(sourceFile, handlerArg.getStart(sourceFile)),
              end_line: getLine(sourceFile, handlerArg.getEnd()),
              params,
              calls,
            };
          } else if (ts.isIdentifier(handlerArg)) {
            handlerRef = handlerArg.text;
          } else if (ts.isCallExpression(handlerArg)) {
            if (ts.isIdentifier(handlerArg.expression)) {
              handlerRef = handlerArg.expression.text;
            } else if (ts.isPropertyAccessExpression(handlerArg.expression)) {
              handlerRef = `${handlerArg.expression.expression.getText(sourceFile)}.${handlerArg.expression.name.text}`;
            }
          } else if (ts.isPropertyAccessExpression(handlerArg)) {
            handlerRef = `${handlerArg.expression.getText(sourceFile)}.${handlerArg.name.text}`;
          }

          routes.push({
            router: routerName,
            method: methodOrUse.toUpperCase(),
            path: routePathValue,
            handler_ref: handlerRef,
            middlewares,
            inline_handler: inlineHandler,
            line: getLine(sourceFile, node.getStart(sourceFile)),
          });
        }
      }

      if (routePath && maybeHttpMethod && HTTP_METHODS.has(methodOrUse) && node.arguments.length >= 1) {
        const handlerArg = node.arguments[node.arguments.length - 1];
        const middlewareArgs = node.arguments.slice(0, -1);
        const middlewares = middlewareArgs.map((m) => m.getText(sourceFile));

        let handlerRef = null;
        let inlineHandler = null;

        if (ts.isArrowFunction(handlerArg) || ts.isFunctionExpression(handlerArg)) {
          const inlineName = `inline_${methodOrUse}_${getLine(sourceFile, handlerArg.getStart(sourceFile))}`;
          const { params, calls } = analyzeFunctionBody(handlerArg, sourceFile);
          inlineHandler = {
            name: inlineName,
            start_line: getLine(sourceFile, handlerArg.getStart(sourceFile)),
            end_line: getLine(sourceFile, handlerArg.getEnd()),
            params,
            calls,
          };
        } else if (ts.isIdentifier(handlerArg)) {
          handlerRef = handlerArg.text;
        } else if (ts.isCallExpression(handlerArg)) {
          if (ts.isIdentifier(handlerArg.expression)) {
            handlerRef = handlerArg.expression.text;
          } else if (ts.isPropertyAccessExpression(handlerArg.expression)) {
            handlerRef = `${handlerArg.expression.expression.getText(sourceFile)}.${handlerArg.expression.name.text}`;
          }
        } else if (ts.isPropertyAccessExpression(handlerArg)) {
          handlerRef = `${handlerArg.expression.getText(sourceFile)}.${handlerArg.name.text}`;
        }

        routes.push({
          router: routeRouterName,
          method: methodOrUse.toUpperCase(),
          path: routePath,
          handler_ref: handlerRef,
          middlewares,
          inline_handler: inlineHandler,
          line: getLine(sourceFile, node.getStart(sourceFile)),
        });
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return { rel_path: relPath, imports, functions, mounts, routes };
}

function main() {
  const targetDir = process.argv[2];
  if (!targetDir || !fs.existsSync(targetDir)) {
    console.error("Usage: node ts_compiler_bridge.js <target_source_dir>");
    process.exit(1);
  }
  const rootDir = path.resolve(targetDir);
  const files = walkFiles(rootDir, rootDir);
  const output = {};
  for (const f of files) {
    try {
      const parsed = parseFile(f, rootDir);
      output[parsed.rel_path] = parsed;
    } catch (err) {
      console.error(`Unable to parse ${path.relative(rootDir, f)}: ${err.message}`);
      process.exitCode = 1;
    }
  }
  process.stdout.write(JSON.stringify(output));
}

main();

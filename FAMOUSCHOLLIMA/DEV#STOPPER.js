// Run the following command to install dependencies:
//  npm install @babel/parser @babel/traverse @babel/generator @babel/types

const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require("@babel/types");

console.log(`
███████╗░██████╗███████╗███╗░░██╗████████╗██╗██████╗░███████╗
██╔════╝██╔════╝██╔════╝████╗░██║╚══██╔══╝██║██╔══██╗██╔════╝
█████╗░░╚█████╗░█████╗░░██╔██╗██║░░░██║░░░██║██████╔╝█████╗░░
██╔══╝░░░╚═══██╗██╔══╝░░██║╚████║░░░██║░░░██║██╔══██╗██╔══╝░░
███████╗██████╔╝███████╗██║░╚███║░░░██║░░░██║██║░░██║███████╗
╚══════╝╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝╚═╝░░╚═╝╚══════╝
`)

const args = process.argv.slice(2);

if (args.length != 2) {
    console.error("Usage: node DEV#STOPPER.js OBFUSCATED.js DEOBFUSCATED.js");
    process.exit(1);
}

console.log("Reading obfuscated code from file:", args[0]);
const js_code = fs.readFileSync(args[0], 'utf-8');

console.log("Parsing file contents into AST");
const ast = parser.parse(js_code, {
    sourceType: 'unambiguous'
});


function evaluateAstMath(node, scope) {
  if (t.isIdentifier(node)) return scope[node.name] !== undefined ? scope[node.name] : node;
  if (t.isNumericLiteral(node)) return node.value;
  if (t.isStringLiteral(node)) return node.value;

  // Handle MemberExpressions (a.b) or (a['b'])
  if (t.isMemberExpression(node)) {
    const objName = node.object.name;
    // Dot notation a.b || string notation a['b']
    const propName = node.property.name || node.property.value;
    
    if (constants[objName] && constants[objName][propName] !== undefined) {
      return constants[objName][propName];
    }
    return node;
  }

  // Handle UnaryExpressions (-val)
  if (t.isUnaryExpression(node) && node.operator === '-') {
    // Recursively evaluate the argument (this handles -a0dY.a (UnaryExpression -> MemberExpression))
    const val = evaluateAstMath(node.argument, scope, constants);
    return typeof val === 'number' ? -val : node;
  }

  // Handle BinaryExpressions (a - b)
  if (t.isBinaryExpression(node)) {
    const left = evaluateAstMath(node.left, scope, constants);
    const right = evaluateAstMath(node.right, scope, constants);
    
    if (typeof left === 'number' && typeof right === 'number') {
      if (node.operator === '-') return left - right;
      if (node.operator === '+') return left + right;
    }
  }

  return node;
}

function getActualValue(node) {
    if (!node) return undefined;

    // Literal Numbers
    if (t.isNumericLiteral(node)) return node.value;
    
    // Literal Strings
    if (t.isStringLiteral(node)) return node.value;

    // Negative Numbers
    if (t.isUnaryExpression(node) && node.operator === '-') {
        return -getActualValue(node.argument);
    }

    // Object Lookups (a0e6.c)
    if (t.isMemberExpression(node)) {
        const obj = node.object.name;
        const prop = node.computed ? node.property.value : node.property.name;
        if (constants[obj] && constants[obj].hasOwnProperty(prop)) {
            return constants[obj][prop];
        }
    }

    return undefined;
}


function decodeCustomBase64(customBase64String) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
    let n = '';
    let o = '';
    let r = 0;
    let q = 0;

    for (let t = 0; t < customBase64String.length; t++) {
        // Lookup
        let s = customBase64String.charAt(t);
        s = alphabet.indexOf(s);

        // Skip characters not in alphabet
        if (s === -1)
        {
            continue;
        }

        // Accumulate bits
        if (q % 4 === 0) {
            r = s;
        } else {
            r = (r * 64) + s;
        }

        q++;

        if (q % 4 !== 1) {
            let shift = (-2 * q) & 6;
            let byte = (r >> shift) & 0xFF;
            n += String.fromCharCode(byte);
        }
    }
    
    for (let u = 0x0, v = n.length; u < v; u++) {
          o += '%' + ('00' + n.charCodeAt(u).toString(0x10)).slice(-0x2);
    }

    return decodeURIComponent(o);
};

function decodeCustomBase64DecryptFromRC4(encodedString, rc4Key) {
    let n = [],
        o = 0x0,
        p,
        q = '';

    let decodedString = decodeCustomBase64(encodedString);
    let r;
    for (r = 0x0; r < 0x100; r++) {
        n[r] = r;
    }
    for (r = 0x0; r < 0x100; r++) {
        o = (o + n[r] + rc4Key.charCodeAt(r % rc4Key.length)) % 0x100, p = n[r], n[r] = n[o], n[o] = p;
    }
    r = 0x0, o = 0x0;
    for (let t = 0x0; t < decodedString.length; t++) {
        r = (r + 0x1) % 0x100, o = (o + n[r]) % 0x100, p = n[r], n[r] = n[o], n[o] = p, q += String.fromCharCode(decodedString.charCodeAt(t) ^ n[(n[r] + n[o]) % 0x100]);
    }
    return q;
};


// Traverse variables for object expressions and extract constants needed for shuffle/index/RC4 key lookups
const constants = {};

traverse(ast, {
    VariableDeclarator(path) {
        if (path.node.init?.type === 'ObjectExpression') {
            const objName = path.node.id.name;
            constants[objName] = {};
            path.node.init.properties.forEach(prop => {
                const key = prop.key?.name || prop.key?.value;
                const valNode = prop.value;
                // Handle both positive and negative values in the dictionary
                constants[objName][key] = valNode?.type === 'UnaryExpression' 
                    ? -valNode.argument.value 
                    : valNode?.value;
            });
        }
    }
});

// Find the function that returns a massive array of base64 encoded strings and store them for later
// The function defines the array once, redefines itself to a simpler version that just returns that array, and then calls that new version.

let encodedStringsArray = [];
let encodedStringsFunctionName = '';
let encodedStringsFunctionPath = null;

traverse(ast, {
  FunctionDeclaration(path) {
    // Traverse variables inside each function
    path.traverse({
      VariableDeclarator(declPath) {
        const { init } = declPath.node;

        // Check if it's an array with length > 200 and contains only strings
        if (t.isArrayExpression(init) && 
            init.elements.length > 200 && 
            init.elements.every(el => t.isStringLiteral(el))) {
          
          const arrayValue = init.elements.map(el => el.value);
          const fnName = path.node.id.name;
          encodedStringsFunctionName = fnName;

          console.log(`Found ${arrayValue.length} encoded strings (shuffled) returned by function "${fnName}".`);
          // Store the array and stop searching this function
          encodedStringsArray = arrayValue;
          encodedStringsFunctionPath = path;
          declPath.stop(); 
        }
      }
    }, path.state); // Ensures we stay within the current function context
  }
});

// Find the shuffler IIFE (Immediately Invoked Function Expression) and extract the "shuffle egg"
// This is an integer passed to the shuffling function to determine when the encoded strings array is in the correct order later
// Two arguments are passed to this function:
//   1. CallExpression of the encoded strings function that returns the encoded strings array
//   2. The "shuffle egg" (the value that determines when the array is re-ordered correctly)

let shuffleEgg = null;
let shuffleFunctionPath = null;

traverse(ast, {
  // Traverse CallExpressions to find the shuffler function
  CallExpression(path) {
    const { callee, arguments: args } = path.node;

    // Check if the thing being called is a function expression
    if (path.get('callee').isFunctionExpression()) {

        // Check if it is an anonymous function that takes 2 parameters
        if (callee.id === null && callee.params.length === 2) {

            // Check if the first argument is the encoded strings function call
            if (args[0].name === encodedStringsFunctionName) {
                const shuffleEggLiteral = args[1];
                console.log("Found shuffle function at line:", path.node.loc.start.line);
                console.log("    [>] Egg:", `0x${shuffleEggLiteral.value.toString(16)}`);
                shuffleEgg = shuffleEggLiteral.value;
                shuffleFunctionPath = path;
            }
        }
    }
  }
});


// Find the decode/decrypt function by pattern matching
let decryptFunctionName = '';
let decryptFunctionPath = null;

traverse(ast, {
    FunctionDeclaration(path) {
        const functionString = path.toString();
        if (functionString.includes('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=') || (functionString.includes("'%' + ('00'") && functionString.includes('0x1) % 0x100'))) {
            decryptFunctionName = path.node.id.name;
            decryptFunctionPath = path;
            console.log(`Found decrypt function name: ${decryptFunctionName}`);
        }
    }
});

// Within the shuffler function, there are several "proxy" callers to the decrypt function
// Identify the calls and associated arguments and save them for later use when "unshuffling"
// the encoded strings array
const proxyMap = {};

traverse(ast, {
    FunctionDeclaration(path) {
        const { id, params, body } = path.node;

        // Look for aReturnStatement in the function's body
        const returnStmt = body.body.find(node => node.type === 'ReturnStatement');
        
        // Does the return statement call the decrypt function and is the function declared inside the shuffler function?
        if (
            returnStmt && 
            returnStmt.argument?.type === 'CallExpression' &&
            returnStmt.argument.callee.name === decryptFunctionName &&
            path.findParent(p => p === shuffleFunctionPath)
        ) {
            const call = returnStmt.argument;
            // Store the name of the function as the key in the proxyMap object and map to associated params/args
            proxyMap[id.name] = {
                params: params.map(p => p.name),
                callArgs: call.arguments
            };

            console.log(`Found decrypt function call "${id.name}" in shuffler function.`);
        }
    }
});

// Traverse variable declarations and find the variable that uses parseInt repeatedly and evaluate the value
// If the value does not match our "shuffle egg", re-shuffle and try again, otherwise we've successfully re-ordered
// the encoded strings array!

traverse(ast, {
  VariableDeclarator(path) {
    const initExpression = path.get('init');
    let parseIntCallCount = 0;

    // Count the amount of parseInt() calls for the variable
    initExpression.traverse({
      CallExpression(callPath) {
        if (callPath.get('callee').isIdentifier({ name: 'parseInt' })) {
          parseIntCallCount++;
        }
      }
    });

    // Skip paths with less than 6 parseInt calls
    if (parseIntCallCount < 6) {
      return;
    }

    // If we found a variable that makes use of parseInt 5 or more times, 
    // it is the variable used in comparison against the shuffle egg

    const originalCallNodes = [];

    console.log(`Target variable expression found! Variable "${path.node.id.name}" is used to store the "running" shuffle value: ${initExpression.toString()}`);

    while (true) {
        // Replace all decode/decrypt function calls with their respective decrypted result string
        // and evaluate the current value of the variable expression to determine if it matches.
        // If it matches, the encoded strings array has been re-ordered successfully, if not, continue looping
        initExpression.traverse({
            CallExpression(callPath) {
                const callee = callPath.get('callee');
                
                // Identify the inner obfuscated calls (e.g., aL, aM, aN)
                // These are the first argument of the parseInt call
                if (callee.isIdentifier({ name: 'parseInt' })) {
                    const innerCall = callPath.get('arguments.0');

                    if (innerCall && innerCall.isCallExpression()) {

                        // Store the original call nodes
                        originalCallNodes.push({
                            path: innerCall,
                            originalNode: t.cloneNode(innerCall.node, true)
                        });

                        // Lookup the function's arguments in our saved object "proxyMap"
                        const callee = innerCall.get('callee');
                        const callArgs = innerCall.get('arguments');
                        const logic = proxyMap[callee.node.name];

                        // Map call-site values to parameter names, e.g. a, b
                        const scope = {};
                        logic.params.forEach((name, i) => {
                            // Resolve literals or constants from your dictionary
                            scope[name] = getActualValue(callArgs[i].node);
                        });

                        // Determine which inner argument is the encoded string index and which is the RC4 key
                        let finalIndex = null;
                        let finalString = null;
                        logic.callArgs.forEach(innerArg => {
                            const val = evaluateAstMath(innerArg, scope);
                            
                            if (typeof val === 'number') {
                                finalIndex = val - 0x151;
                            } else if (typeof val === 'string') {
                                finalString = val;
                            }
                        });

                        let encodedString = encodedStringsArray[finalIndex]
                        const decryptedValue = decodeCustomBase64DecryptFromRC4(encodedString, finalString);

                        // Replace current call to decrypt function with decrypted value, resulting in code replacement resembling:
                        // const d = parseInt("<decryptedValue1>") / 0x1 + parseInt("<decryptedValue2>")
                        innerCall.replaceWith(t.stringLiteral(decryptedValue));
                    }
                }   
            }
        });

        // Evaluate to see if we found our egg
        const evaluation = initExpression.evaluate();
        if (evaluation.confident && evaluation.value === shuffleEgg) {
            console.log(`Egg "0x${shuffleEgg.toString(16)}" has been found via code "${initExpression.toString()}", successfully re-ordered the encoded strings array.`);
            break;
        }
        // If not shuffle once and continue searching
        else {
            originalCallNodes.forEach(({ path, originalNode }) => {
                path.replaceWith(originalNode);
                path.resync();
            });

            encodedStringsArray.push(encodedStringsArray.shift());
        }
    }
}});

// Handle nested proxy calls, where the decrypt function is buried
function traceDownToDecryptFunction(callPath, scope, constants) {
  const calleeName = callPath.node.callee.name;

  // Evaluate the arguments for the current call
  const resolvedArgs = callPath.node.arguments.map(arg => 
    evaluateAstMath(arg, scope, constants)
  );

  // Success: We hit the target
  if (calleeName === decryptFunctionName) {
    return resolvedArgs;
  }

  // Find the definition of the function we are currently calling
  const binding = callPath.scope.getBinding(calleeName);
  if (!binding || !t.isFunctionDeclaration(binding.path.node)) return null;

  const fnPath = binding.path;
  const params = fnPath.node.params;

  // Map the parameters of the function definition to the resolved arguments
  const nextScope = {};
  params.forEach((param, i) => {
    if (t.isIdentifier(param)) {
      nextScope[param.name] = resolvedArgs[i];
    }
  });

  // Drill deeper, look for the next CallExpression in the ReturnStatement
  let finalResult = null;
  fnPath.traverse({
    ReturnStatement(retPath) {
      const arg = retPath.node.argument;
      if (t.isCallExpression(arg)) {
        finalResult = traceDownToDecryptFunction(retPath.get("argument"), nextScope, constants);
      }
      retPath.stop();
    }
  });

  return finalResult;
}

// We need to find all functions that eventually call the decrypt function
// and determine what the values of the arguments are when passed into the decrypt function
// With these values we lookup the original string, decode it, decrypt it, and replace the 
// call with the resulting string literal

traverse(ast, {
CallExpression(path) {
    const callee = path.node.callee;
    
    // Basic check to skip the actual target function calls to avoid recursion loops
    if (t.isIdentifier(callee) && callee.name === decryptFunctionName) return;
    
    // Check to ensure parent is not a proxy function
    if (path.parent.type === "ReturnStatement" && path.parentPath?.parent.type === "BlockStatement" && path.parentPath?.parent.body.length === 1) return;

    // Trace every call, if it leads to the decrypt function, capture the args at the decrypt function call-site
    // and replace the call expression with the evaluated string literal
    const args = traceDownToDecryptFunction(path, {}, constants, ast);

    // If arguments weren't resolved, skip
    if (!args) return;
  
    if (callee.name === "aL") {
      console.log(`Drilled down on proxy function call ${callee.name}, args: ${args}`);
    }

    let index = args[0];
    let rc4Key = args[1];
    
    // Subtract via constant
    let finalIndex = index - 0x151 
    let encodedString = encodedStringsArray[finalIndex % encodedStringsArray.length]
    if (encodedString && rc4Key) {
        let decryptedString = decodeCustomBase64DecryptFromRC4(encodedString, rc4Key);
        console.log(`Decrypted string: ${decryptedString}`);
        path.replaceWith(t.stringLiteral(decryptedString));
    }
    else {
      console.log(`Fucked up down on proxy function call ${callee.name}, args: ${args}`);
    }
    
}});


// Fold string literals like "abc" + "def"
traverse(ast, {
  BinaryExpression(path) {
    // Skip binary expressions that don't use the + operator
    if (path.node.operator !== '+') {
      return;
    }
    // Evaluate the expression and check if it's a string
    const result = path.evaluate();
    if (result.confident && typeof result.value === 'string') {
      // Replace the expression with the string literal
      path.replaceWith(t.stringLiteral(result.value));
    }
  }
});

// Traverse via VariableDeclarator to find/save constants (again)
const newConstants = {};

traverse(ast, {
    VariableDeclarator(path) {
        const { id, init } = path.node;
        
        // Find: const anyObj = { key: 'val', ... }
        if (t.isIdentifier(id) && t.isObjectExpression(init)) {
            const objName = id.name;
            newConstants[objName] = {};

            init.properties.forEach(prop => {
                // Handle both { key: 'val' } and { 'key': 'val' }
                const propKey = t.isIdentifier(prop.key) ? prop.key?.name : prop.key?.value;
                
                if (t.isLiteral(prop.value)) {
                    newConstants[objName][propKey] = prop.value.value;
                }
            });
        }
    }
});

// Traverse member expressions and replace bracket notation with string literal

traverse(ast, {
    MemberExpression(path) {
        const { node } = path;

        // If the access type is in dot notation, skip this member expression
        if (!node.computed) return;

        // Ensure the property is a StringLiteral to avoid crashing on o[variable]
        if (!t.isStringLiteral(node.property)) return;

        const objectName = node.object.name;
        const key = node.property.value;

        // Look up the value in the saved constants
        if (newConstants[objectName] && newConstants[objectName].hasOwnProperty(key)) {
            const actualValue = newConstants[objectName][key];
            
            // Replace the member expression with the string literal
            let newNode;
            if (typeof actualValue === 'string') {
                newNode = t.stringLiteral(actualValue);
                newNode.extra = { rawValue: actualValue, raw: `'${actualValue}'` };
            }

            if (newNode) {
                console.log(`Mapping ${objectName}['${key}'] -> ${actualValue}`);
                path.replaceWith(newNode);
            }
        }
    }
});

// Convert object-method calls to original operator notation, e.g.:
// 'GfhJQ': function (J, K) {
//        return J < K;
//      },

const methodMap = {};

traverse(ast, {
  // Find the Mapping Object (e.g., var _0xabc = { ... })
  ObjectProperty(path) {
    const { key, value } = path.node;
    const name = key.name || key.value;

    // Check if the value is a function that returns something
    if (t.isFunctionExpression(value) && t.isReturnStatement(value.body.body[0])) {
      const returnArgument = value.body.body[0].argument;

      // Store the a map based on the return type for use in replacing call expression with the original expression
      if (t.isBinaryExpression(returnArgument)) {
        methodMap[name] = { type: 'binary', operator: returnArgument.operator };
      } else if (t.isLogicalExpression(returnArgument)) {
        methodMap[name] = { type: 'logical', operator: returnArgument.operator };
      } else if (t.isCallExpression(returnArgument)) {
        methodMap[name] = { type: 'proxy' };
      }
    }
  },

  // Replace call expressions
  CallExpression(path) {
    const { callee, arguments: args } = path.node;
    
    // Match patterns like obj['method'](args) or obj.method(args)
    let methodName;
    if (t.isMemberExpression(callee)) {
      methodName = callee.property.name || callee.property.value;
    }

    if (methodMap[methodName]) {
      const meta = methodMap[methodName];

      if (meta.type === 'binary') {
        path.replaceWith(t.binaryExpression(meta.operator, args[0], args[1]));
      } 
      else if (meta.type === 'logical') {
        path.replaceWith(t.logicalExpression(meta.operator, args[0], args[1]));
      } 
      else if (meta.type === 'proxy') {
        // The first argument becomes the caller, rest are arguments
        const [actualCallee, ...actualArgs] = args;
        path.replaceWith(t.callExpression(actualCallee, actualArgs));
      }
    }
  }
});

// Convert string notation method calls like a['startsWith'] to dot notation a.startsWith
traverse(ast, {
  MemberExpression(path) {
    const { property, computed } = path.node;

    // Check if the member expression uses string notation, e.g. a['startswith']
    if (computed && t.isStringLiteral(property)) {
      // Change the property from a StringLiteral to an Identifier
      path.node.property = t.identifier(property.value);
      
      // Set computed to false to switch to dot notation (z.startsWith)
      path.node.computed = false;
    }
  }
});

// Cleanup

// Remove the decode/decrypt function
decryptFunctionPath.remove();
// Remove the encoded strings array function
encodedStringsFunctionPath.remove();
// Remove the anonymous shuffler function
shuffleFunctionPath.remove();

// Clean up unused variables and functions that are no longer referenced
function cleanupUnusedVariablesAndFunctions(ast) {
  let modified;
  do {
    modified = false;
    // We crawl the scope at the start of every pass to get fresh reference counts
    ast.program && traverse(ast, {
      Program(path) {
        path.scope.crawl();
      }
    });

    traverse(ast, {
      // Targets: var x = 1, function x() {}, const x = () => {}
      "VariableDeclarator|FunctionDeclaration"(path) {
        const { id } = path.node;

        if (t.isIdentifier(id)) {
          const binding = path.scope.getBinding(id.name);

          if (binding && !binding.referenced && !path.parentPath.isExportDeclaration()) {
            console.log(`Purging unused: ${id.name}`);
            path.remove();
            modified = true;
          }
        }
      }
    });
  } while (modified);
}

cleanupUnusedVariablesAndFunctions(ast);

// Clean up \x
traverse(ast, {
  StringLiteral(path) {
    delete path.node.extra;
  }
});


// Save the modified AST
console.log("Saving modified AST");
const output = generate(ast, {
  comments: true,
  compact: false,
  minified: false,
  concise: false,
  retainLines: false,
  jsescOption: {
    minimal: true,
    quotes: "single",
  },
  indent: {
    style: "  ",
  },
}).code;

fs.writeFileSync(args[1], output);
console.log(`Successfully deobfuscated to: ${args[1]}`);

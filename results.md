Snyk test report {.project__header__title}
================

March 6th 2020, 3:18:25 pm

Scanned the following path:

-   /Users/mattbrown/Desktop/DemoPrograms/Goofs/goof (npm)

47 known vulnerabilities

221 vulnerable dependency paths

471 dependencies

Denial of Service (DoS) {.card__title}
-----------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: express-fileupload
-   Introduced through: goof@1.0.1 and express-fileupload@0.0.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › express-fileupload@0.0.5

* * * * *

Overview
--------

[express-fileupload](https://github.com/richardgirges/express-fileupload)
is a file upload middleware for express that wraps around busboy.

Affected versions of this package are vulnerable to Denial of Service
(DoS). The package does not limit file name length.

Details
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its intended and legitimate users.

Unlike other vulnerabilities, DoS attacks usually do not aim at
breaching security. Rather, they are focused on making websites and
services unavailable to genuine users resulting in downtime.

One popular Denial of Service vulnerability is DDoS (a Distributed
Denial of Service), an attack that attempts to clog network pipes to the
system by generating a large volume of traffic from many machines.

When it comes to open source libraries, DoS vulnerabilities allow
attackers to trigger such a crash or crippling of the service by using a
flaw either in the application code or from the use of open source
libraries.

Two common types of DoS vulnerabilities:

-   High CPU/Memory Consumption- An attacker sending crafted requests
    that could cause the system to take a disproportionate amount of
    time to process. For example,
    [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).

-   Crash - An attacker sending crafted requests that could cause the
    system to crash. For Example, [npm `ws` package](npm:ws:20171108)

Remediation
-----------

Upgrade `express-fileupload` to version 1.1.6-alpha.6 or higher.

References
----------

-   [GitHub
    PR](https://github.com/richardgirges/express-fileupload/pull/171)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-EXPRESSFILEUPLOAD-473997)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: handlebars
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-reports@1.4.0 › handlebars@4.0.11

* * * * *

Overview {#overview}
--------

[handlebars](https://www.npmjs.com/package/handlebars) is a extension to
the Mustache templating language.

Affected versions of this package are vulnerable to Prototype Pollution.
Templates may alter an Objects' prototype, thus allowing an attacker to
execute arbitrary code on the server.

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type:

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `handlebars` to version 4.0.14, 4.1.2 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/wycats/handlebars.js/commit/7372d4e9dffc9d70c09671aa28b9392a1577fd86)

-   [GitHub Issue](https://github.com/wycats/handlebars.js/issues/1495)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/755)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-173692)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: handlebars
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-reports@1.4.0 › handlebars@4.0.11

* * * * *

Overview {#overview}
--------

[handlebars](https://www.npmjs.com/package/handlebars) is a extension to
the Mustache templating language.

Affected versions of this package are vulnerable to Prototype Pollution.
A Prototype Pollution allowing Remote Code Execution can be exploited
using the constructor, via the 'lookup' helper. This vulnerability is
due to an incomplete fix for: `SNYK-JS-HANDLEBARS-173692`

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `handlebars` to version 3.0.7, 4.1.2, 4.0.14 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/wycats/handlebars.js/commit/cd38583216dce3252831916323202749431c773e)

-   [GitHub Issue](https://github.com/wycats/handlebars.js/issues/1495)

-   [SNYK-JS-HANDLEBARS-173692](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-173692)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-174183)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: handlebars
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-reports@1.4.0 › handlebars@4.0.11

* * * * *

Overview {#overview}
--------

[handlebars](https://www.npmjs.com/package/handlebars) is a extension to
the Mustache templating language.

Affected versions of this package are vulnerable to Prototype Pollution.
Templates may alter an Object's `__proto__` and `__defineGetter__`
properties, which may allow an attacker to execute arbitrary code on the
server through crafted payloads.

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `handlebars` to version 4.3.0, 3.8.0 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/wycats/handlebars.js/commit/213c0bbe3c4bd83a534d67384e5afa0000347ff6)

-   [GitHub
    Commit](https://github.com/wycats/handlebars.js/commit/7b67a29a8c926b38af265c727ff6551fbb277111)

-   [GitHub Issue](https://github.com/wycats/handlebars.js/issues/1558)

-   [Reference](https://www.npmjs.com/advisories/1164)

-   [Release
    Notes](https://github.com/wycats/handlebars.js/blob/master/release-notes.md#v430---september-24th-2019)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-469063)

Denial of Service (DoS) {.card__title}
-----------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: handlebars
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-reports@1.4.0 › handlebars@4.0.11

* * * * *

Overview {#overview}
--------

[handlebars](https://www.npmjs.com/package/handlebars) is an extension
to the Mustache templating language.

Affected versions of this package are vulnerable to Denial of Service
(DoS). The package's parser may be forced into an endless loop while
processing specially-crafted templates, which may allow attackers to
exhaust system resources leading to Denial of Service.

Remediation {#remediation}
-----------

Upgrade `handlebars` to version 4.4.5 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/wycats/handlebars.js/commit/8d5530ee2c3ea9f0aee3fde310b9f36887d00b8b)

-   [GitHub Issue](https://github.com/wycats/handlebars.js/issues/1579)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1300)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-480388)

Arbitrary Code Execution {.card__title}
------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: handlebars
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-reports@1.4.0 › handlebars@4.0.11

* * * * *

Overview {#overview}
--------

[handlebars](https://www.npmjs.com/package/handlebars) is a extension to
the Mustache templating language.

Affected versions of this package are vulnerable to Arbitrary Code
Execution. The package's lookup helper doesn't validate templates
correctly, allowing attackers to submit templates that execute arbitrary
JavaScript in the system.

Remediation {#remediation}
-----------

Upgrade `handlebars` to version 4.5.3, 3.0.8 or higher.

References {#references}
----------

-   [NPM Security Advisory \#1](https://www.npmjs.com/advisories/1316)

-   [NPM Security Advisory \#2](https://www.npmjs.com/advisories/1324)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-534478)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: handlebars
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-reports@1.4.0 › handlebars@4.0.11

* * * * *

Overview {#overview}
--------

[handlebars](https://www.npmjs.com/package/handlebars) is an extension
to the Mustache templating language.

Affected versions of this package are vulnerable to Prototype Pollution.
It is possible to add or modify properties to the Object prototype
through a malicious template. This may allow attackers to crash the
application or execute Arbitrary Code in specific conditions.

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `handlebars` to version 4.5.3, 3.0.8 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/wycats/handlebars.js/commit/198887808780bbef9dba67a8af68ece091d5baa7)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1325)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-HANDLEBARS-534988)

Prototype Pollution {.card__title}
-------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: jquery
-   Introduced through: goof@1.0.1 and jquery@2.2.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › jquery@2.2.4

* * * * *

Overview {#overview}
--------

[jquery](https://www.npmjs.com/package/jquery) is a JavaScript library.
It makes things like HTML document traversal and manipulation, event
handling, animation, and Ajax much simpler with an easy-to-use API that
works across a multitude of browsers.

Affected versions of this package are vulnerable to Prototype Pollution.
The `extend` function can be tricked into modifying the prototype of
`Object` when the attacker controls part of the structure passed to this
function. This can let an attacker add or modify an existing property
that will then exist on all objects.

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `jquery` to version 3.4.0 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b)

-   [GitHub PR](https://github.com/jquery/jquery/pull/4333)

-   [Hackerone Report](https://hackerone.com/reports/454365)

-   [Snyk
    Blog](https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/)

-   [Third-Party Backported Patches
    Repo](https://github.com/DanielRuf/snyk-js-jquery-174006)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-JQUERY-174006)

Cross-site Scripting (XSS) {.card__title}
--------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: jquery
-   Introduced through: goof@1.0.1 and jquery@2.2.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › jquery@2.2.4

* * * * *

Overview {#overview}
--------

[jquery](https://www.npmjs.com/package/jquery) is a JavaScript library.
It makes things like HTML document traversal and manipulation, event
handling, animation, and Ajax much simpler with an easy-to-use API that
works across a multitude of browsers.

Affected versions of this package are vulnerable to Cross-site Scripting
(XSS) attacks when a cross-domain ajax request is performed without the
`dataType` option causing `text/javascript` responses to be executed.

Details {#details}
-------

A cross-site scripting attack occurs when the attacker tricks a
legitimate web-based application or site to accept a request as
originating from a trusted source.

This is done by escaping the context of the web application; the web
application then delivers that data to its users along with other
trusted dynamic content, without validating it. The browser unknowingly
executes malicious script on the client side (through client-side
languages; usually JavaScript or HTML) in order to perform actions that
are otherwise typically blocked by the browser’s Same Origin Policy.

ֿInjecting malicious code is the most prevalent manner by which XSS is
exploited; for this reason, escaping characters in order to prevent this
manipulation is the top method for securing code against this
vulnerability.

Escaping means that the application is coded to mark key characters, and
particularly key characters included in user input, to prevent those
characters from being interpreted in a dangerous context. For example,
in HTML, `<` can be coded as `&lt`; and `>` can be coded as `&gt`; in
order to be interpreted and displayed as themselves in text, while
within the code itself, they are used for HTML tags. If malicious
content is injected into an application that escapes special characters
and that malicious content uses `<` and `>` as HTML tags, those
characters are nonetheless not interpreted as HTML tags by the browser
if they’ve been correctly escaped in the application code and in this
way the attempted attack is diverted.

The most prominent use of XSS is to steal cookies (source: OWASP
HttpOnly) and hijack user sessions, but XSS exploits have been used to
expose sensitive information, enable access to privileged services and
functionality and deliver malware.

### Types of attacks {#types-of-attacks}

There are a few methods by which XSS can be manipulated:

  Type            Origin   Description
  --------------- -------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Stored**      Server   The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.
  **Reflected**   Server   The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.
  **DOM-based**   Client   The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.
  **Mutated**              The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.

### Affected environments {#affected-environments}

The following environments are susceptible to an XSS attack:

-   Web servers
-   Application servers
-   Web application environments

### How to prevent {#how-to-prevent}

This section describes the top best practices designed to specifically
protect your code:

-   Sanitize data input in an HTTP request before reflecting it back,
    ensuring all data is validated, filtered or escaped before echoing
    anything back to the user, such as the values of query parameters
    during searches.
-   Convert special characters such as `?`, `&`, `/`, `<`, `>` and
    spaces to their respective HTML or URL encoded equivalents.
-   Give users the option to disable client-side scripts.
-   Redirect invalid requests.
-   Detect simultaneous logins, including those from two separate IP
    addresses, and invalidate those sessions.
-   Use and enforce a Content Security Policy (source: Wikipedia) to
    disable any features that might be manipulated for an XSS attack.
-   Read the documentation for any of the libraries referenced in your
    code to understand which elements allow for embedded HTML.

Remediation {#remediation}
-----------

Upgrade `jquery` to version 1.12.2, 2.2.2, 3.0.0 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/jquery/jquery/commit/f60729f3903d17917dc351f3ac87794de379b0cc)

-   [GitHub
    Commit](https://github.com/jquery/jquery/pull/2588/commits/c254d308a7d3f1eac4d0b42837804cfffcba4bb2)

-   [GitHub Issue](https://github.com/jquery/jquery/issues/2432)

-   [GitHub PR](https://github.com/jquery/jquery/pull/2588)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:jquery:20150627)

Information Disclosure {.card__title}
----------------------

low severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: kind-of
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › to-regex@3.0.2 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › use@3.1.0 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › use@3.1.0 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › use@3.1.0 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › to-regex@3.0.2 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › to-regex@3.0.2 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon-node@2.1.1 ›
    define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    define-property@2.0.2 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon-node@2.1.1 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon-node@2.1.1 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › to-regex@3.0.2 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › base@0.11.2
    › define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    base@0.11.2 › define-property@1.0.0 › is-descriptor@1.0.2 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon-node@2.1.1 › define-property@1.0.0 › is-descriptor@1.0.2
    › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › use@3.1.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › base@0.11.2
    › define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    base@0.11.2 › define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon-node@2.1.1 › define-property@1.0.0 › is-descriptor@1.0.2
    › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › base@0.11.2
    › define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    base@0.11.2 › define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon-node@2.1.1 › define-property@1.0.0 › is-descriptor@1.0.2
    › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    to-regex@3.0.2 › define-property@2.0.2 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › to-regex@3.0.2 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › to-regex@3.0.2 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › base@0.11.2 › define-property@1.0.0 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › to-regex@3.0.2 › define-property@2.0.2 ›
    is-descriptor@1.0.2 › is-data-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-accessor-descriptor@1.0.0 › kind-of@6.0.2
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › base@0.11.2 ›
    define-property@1.0.0 › is-descriptor@1.0.2 ›
    is-data-descriptor@1.0.0 › kind-of@6.0.2

* * * * *

Overview {#overview}
--------

[kind-of](https://github.com/jonschlinkert/kind-of) is a package that
gets the native type of a value.

Affected versions of this package are vulnerable to Information
Disclosure. It leverages the built-in constructor of unsafe user-input
to detect type information. However, a crafted payload can overwrite
this built in attribute to manipulate the type detection result.

PoC by Feng Xiao
----------------

    var kindOf = require('kind-of');
              
              
              var user_input = {
                user: 'barney',
                age: 36,
                active: true,
                "constructor":{"name":"Symbol"}
              };
              console.log(kindOf(user_input));

Remediation {#remediation}
-----------

Upgrade `kind-of` to version 6.0.3 or higher.

References {#references}
----------

-   [GitHub Issue](https://github.com/jonschlinkert/kind-of/issues/30)

-   [GitHub PR](https://github.com/jonschlinkert/kind-of/pull/31)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-KINDOF-537849)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: lodash
-   Introduced through: goof@1.0.1 and lodash@4.17.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › lodash@4.17.4
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-generator@6.26.1 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-traverse@6.26.0 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-generator@6.26.1 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-traverse@6.26.0 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-traverse@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-traverse@6.26.0 › babel-types@6.26.0 › lodash@4.17.10

* * * * *

Overview {#overview}
--------

[lodash](https://www.npmjs.com/package/lodash) is a modern JavaScript
utility library delivering modularity, performance, & extras.

Affected versions of this package are vulnerable to Prototype Pollution.
The function `defaultsDeep` could be tricked into adding or modifying
properties of `Object.prototype` using a `constructor` payload.

PoC by Snyk
-----------

    const mergeFn = require('lodash').defaultsDeep;
              const payload = '{"constructor": {"prototype": {"a0": true}}}'
              
              function check() {
                  mergeFn({}, JSON.parse(payload));
                  if (({})[`a0`] === true) {
                      console.log(`Vulnerable to Prototype Pollution via ${payload}`);
                  }
                }
              
              check();

For more information, check out our [blog
post](https://snyk.io/blog/snyk-research-team-discovers-severe-prototype-pollution-security-vulnerabilities-affecting-all-versions-of-lodash/)

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `lodash` to version 4.17.12 or higher.

References {#references}
----------

-   [GitHub Issue](https://github.com/lodash/lodash/issues/4348)

-   [GitHub PR](https://github.com/lodash/lodash/pull/4336)

-   [GitHub PR](https://github.com/lodash/lodash/pull/4355)

-   [GitHub PR](https://github.com/sailshq/lodash/pull/1)

-   [Node Security Advisory](https://www.npmjs.com/advisories/1065)

-   [Snyk
    Blog](https://snyk.io/blog/snyk-research-team-discovers-severe-prototype-pollution-security-vulnerabilities-affecting-all-versions-of-lodash/)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-LODASH-450202)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: lodash
-   Introduced through: goof@1.0.1 and lodash@4.17.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › lodash@4.17.4
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-generator@6.26.1 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-traverse@6.26.0 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-generator@6.26.1 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-traverse@6.26.0 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-traverse@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-traverse@6.26.0 › babel-types@6.26.0 › lodash@4.17.10

* * * * *

Overview {#overview}
--------

[lodash](https://www.npmjs.com/package/lodash) is a modern JavaScript
utility library delivering modularity, performance, & extras.

Affected versions of this package are vulnerable to Prototype Pollution.
The functions `merge`, `mergeWith`, and `defaultsDeep` could be tricked
into adding or modifying properties of `Object.prototype`. This is due
to an incomplete fix to `CVE-2018-3721`.

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `lodash` to version 4.17.11 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/lodash/lodash/commit/90e6199a161b6445b01454517b40ef65ebecd2ad)

-   [GitHub PR](https://github.com/lodash/lodash/pull/4337)

-   [HackerOne Report](https://hackerone.com/reports/380873)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1066)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1068)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1071)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/782)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-LODASH-73638)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: lodash
-   Introduced through: goof@1.0.1 and lodash@4.17.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › lodash@4.17.4
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-generator@6.26.1 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-traverse@6.26.0 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-generator@6.26.1 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-traverse@6.26.0 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-types@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-traverse@6.26.0 › lodash@4.17.10
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    istanbul-lib-instrument@1.10.1 › babel-template@6.26.0 ›
    babel-traverse@6.26.0 › babel-types@6.26.0 › lodash@4.17.10

* * * * *

Overview {#overview}
--------

[lodash](https://www.npmjs.com/package/lodash) is a modern JavaScript
utility library delivering modularity, performance, & extras.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). It parses dates using regex strings, which
may cause a slowdown of 2 seconds per 50k characters.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `lodash` to version 4.17.11 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/lodash/lodash/commit/5c08f18d365b64063bfbfa686cbb97cdd6267347)

-   [GitHub Issue](https://github.com/lodash/lodash/issues/3359)

-   [GitHub PR](https://github.com/lodash/lodash/pull/4450)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-LODASH-73639)

Prototype Pollution {.card__title}
-------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: lodash
-   Introduced through: goof@1.0.1 and lodash@4.17.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › lodash@4.17.4

* * * * *

Overview {#overview}
--------

[lodash](https://www.npmjs.com/package/lodash) is a modern JavaScript
utility library delivering modularity, performance, & extras.

Affected versions of this package are vulnerable to Prototype Pollution.
The utilities function allow modification of the `Object` prototype. If
an attacker can control part of the structure passed to this function,
they could add or modify an existing property.

PoC by Olivier Arteau (HoLyVieR)
--------------------------------

    var _= require('lodash');
              var malicious_payload = '{"__proto__":{"oops":"It works !"}}';
              
              var a = {};
              console.log("Before : " + a.oops);
              _.merge({}, JSON.parse(malicious_payload));
              console.log("After : " + a.oops);

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `lodash` to version 4.17.5 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a)

-   [GitHub PR](https://github.com/lodash/lodash/pull/4337)

-   [HackerOne Report](https://hackerone.com/reports/310443)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1067)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1069)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1070)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:lodash:20180130)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). The `inline.text regex` may take quadratic
time to scan for potential email addresses starting at every point.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.6.2 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/markedjs/marked/commit/00f1f7a23916ef27186d0904635aa3509af63d47)

-   [GitHub
    Commit](https://github.com/markedjs/marked/pull/1460/commits/be27472a8169dda7875330939f8115ab677cdc07)

-   [GitHub PR](https://github.com/markedjs/marked/pull/1460)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/812)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-MARKED-174116)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). A Denial of Service condition could be
triggered through exploitation of the `heading` regex.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.4.0 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/markedjs/marked/commit/09afabf69c6d0c919c03443f47bdfe476566105d)

-   [GitHub PR](https://github.com/markedjs/marked/pull/1224)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-MARKED-451540)

Content & Code Injection (XSS) {.card__title}
------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Content & Code
Injection (XSS). An attacker could bypass its output sanitization
(`sanitize: true`) protection. Using the [HTML Coded Character
Set](https://www.w3.org/MarkUp/html-spec/html-spec_13.html#SEC13),
attackers can inject `javascript:` code snippets into the output. For
example, the following input `javascript&#x58document;alert&#40;1&#41;`
will result in `alert(1)` being executed when the user clicks on the
link.

Details {#details}
-------

A cross-site scripting attack occurs when the attacker tricks a
legitimate web-based application or site to accept a request as
originating from a trusted source.

This is done by escaping the context of the web application; the web
application then delivers that data to its users along with other
trusted dynamic content, without validating it. The browser unknowingly
executes malicious script on the client side (through client-side
languages; usually JavaScript or HTML) in order to perform actions that
are otherwise typically blocked by the browser’s Same Origin Policy.

ֿInjecting malicious code is the most prevalent manner by which XSS is
exploited; for this reason, escaping characters in order to prevent this
manipulation is the top method for securing code against this
vulnerability.

Escaping means that the application is coded to mark key characters, and
particularly key characters included in user input, to prevent those
characters from being interpreted in a dangerous context. For example,
in HTML, `<` can be coded as `&lt`; and `>` can be coded as `&gt`; in
order to be interpreted and displayed as themselves in text, while
within the code itself, they are used for HTML tags. If malicious
content is injected into an application that escapes special characters
and that malicious content uses `<` and `>` as HTML tags, those
characters are nonetheless not interpreted as HTML tags by the browser
if they’ve been correctly escaped in the application code and in this
way the attempted attack is diverted.

The most prominent use of XSS is to steal cookies (source: OWASP
HttpOnly) and hijack user sessions, but XSS exploits have been used to
expose sensitive information, enable access to privileged services and
functionality and deliver malware.

### Types of attacks {#types-of-attacks}

There are a few methods by which XSS can be manipulated:

  Type            Origin   Description
  --------------- -------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Stored**      Server   The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.
  **Reflected**   Server   The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.
  **DOM-based**   Client   The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.
  **Mutated**              The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.

### Affected environments {#affected-environments}

The following environments are susceptible to an XSS attack:

-   Web servers
-   Application servers
-   Web application environments

### How to prevent {#how-to-prevent}

This section describes the top best practices designed to specifically
protect your code:

-   Sanitize data input in an HTTP request before reflecting it back,
    ensuring all data is validated, filtered or escaped before echoing
    anything back to the user, such as the values of query parameters
    during searches.
-   Convert special characters such as `?`, `&`, `/`, `<`, `>` and
    spaces to their respective HTML or URL encoded equivalents.
-   Give users the option to disable client-side scripts.
-   Redirect invalid requests.
-   Detect simultaneous logins, including those from two separate IP
    addresses, and invalidate those sessions.
-   Use and enforce a Content Security Policy (source: Wikipedia) to
    disable any features that might be manipulated for an XSS attack.
-   Read the documentation for any of the libraries referenced in your
    code to understand which elements allow for embedded HTML.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.3.6 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/chjj/marked/pull/592/commits/2cff85979be8e7a026a9aca35542c470cf5da523)

-   [GitHub PR](https://github.com/chjj/marked/pull/592)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:marked:20150520)

Cross-site Scripting (XSS) via Data URIs {.card__title}
----------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Cross-site Scripting
(XSS) via Data URIs. Data URIs enable embedding small files in line in
HTML documents, provided in the URL itself. Attackers can craft
malicious web pages containing either HTML or script code that utilizes
the data URI scheme, allowing them to bypass access controls or steal
sensitive information.

An example of data URI used to deliver javascript code. The data holds
`<script>alert('XSS')</script>` tag in base64 encoded format.

    [xss link](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)

Details {#details}
-------

A cross-site scripting attack occurs when the attacker tricks a
legitimate web-based application or site to accept a request as
originating from a trusted source.

This is done by escaping the context of the web application; the web
application then delivers that data to its users along with other
trusted dynamic content, without validating it. The browser unknowingly
executes malicious script on the client side (through client-side
languages; usually JavaScript or HTML) in order to perform actions that
are otherwise typically blocked by the browser’s Same Origin Policy.

ֿInjecting malicious code is the most prevalent manner by which XSS is
exploited; for this reason, escaping characters in order to prevent this
manipulation is the top method for securing code against this
vulnerability.

Escaping means that the application is coded to mark key characters, and
particularly key characters included in user input, to prevent those
characters from being interpreted in a dangerous context. For example,
in HTML, `<` can be coded as `&lt`; and `>` can be coded as `&gt`; in
order to be interpreted and displayed as themselves in text, while
within the code itself, they are used for HTML tags. If malicious
content is injected into an application that escapes special characters
and that malicious content uses `<` and `>` as HTML tags, those
characters are nonetheless not interpreted as HTML tags by the browser
if they’ve been correctly escaped in the application code and in this
way the attempted attack is diverted.

The most prominent use of XSS is to steal cookies (source: OWASP
HttpOnly) and hijack user sessions, but XSS exploits have been used to
expose sensitive information, enable access to privileged services and
functionality and deliver malware.

### Types of attacks {#types-of-attacks}

There are a few methods by which XSS can be manipulated:

  Type            Origin   Description
  --------------- -------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Stored**      Server   The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.
  **Reflected**   Server   The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.
  **DOM-based**   Client   The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.
  **Mutated**              The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.

### Affected environments {#affected-environments}

The following environments are susceptible to an XSS attack:

-   Web servers
-   Application servers
-   Web application environments

### How to prevent {#how-to-prevent}

This section describes the top best practices designed to specifically
protect your code:

-   Sanitize data input in an HTTP request before reflecting it back,
    ensuring all data is validated, filtered or escaped before echoing
    anything back to the user, such as the values of query parameters
    during searches.
-   Convert special characters such as `?`, `&`, `/`, `<`, `>` and
    spaces to their respective HTML or URL encoded equivalents.
-   Give users the option to disable client-side scripts.
-   Redirect invalid requests.
-   Detect simultaneous logins, including those from two separate IP
    addresses, and invalidate those sessions.
-   Use and enforce a Content Security Policy (source: Wikipedia) to
    disable any features that might be manipulated for an XSS attack.
-   Read the documentation for any of the libraries referenced in your
    code to understand which elements allow for embedded HTML.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.3.7 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/chjj/marked/commit/cd2f6f5b7091154c5526e79b5f3bfb4d15995a51)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:marked:20170112)

Cross-site Scripting (XSS) {.card__title}
--------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Cross-site Scripting
(XSS). Browsers support both lowercase and uppercase x in hexadecimal
form of HTML character entity, but marked [unescaped only
lowercase](https://github.com/chjj/marked/blob/v0.3.7/lib/marked.js#L1096-L1108).

This may allow an attacker to create a link with javascript code.

For example:

    var marked = require('marked');
              marked.setOptions({
                renderer: new marked.Renderer(),
                sanitize: true
              });
              
              text = `
              lower[click me](javascript&#x3a;...)lower
              upper[click me](javascript&#X3a;...)upper
              `;
              
              console.log(marked(text));

will render the following:

    <p>lowerlower
              upper<a href="javascript&#X3a;...">click me</a>upper</p>
              

Details {#details}
-------

A cross-site scripting attack occurs when the attacker tricks a
legitimate web-based application or site to accept a request as
originating from a trusted source.

This is done by escaping the context of the web application; the web
application then delivers that data to its users along with other
trusted dynamic content, without validating it. The browser unknowingly
executes malicious script on the client side (through client-side
languages; usually JavaScript or HTML) in order to perform actions that
are otherwise typically blocked by the browser’s Same Origin Policy.

ֿInjecting malicious code is the most prevalent manner by which XSS is
exploited; for this reason, escaping characters in order to prevent this
manipulation is the top method for securing code against this
vulnerability.

Escaping means that the application is coded to mark key characters, and
particularly key characters included in user input, to prevent those
characters from being interpreted in a dangerous context. For example,
in HTML, `<` can be coded as `&lt`; and `>` can be coded as `&gt`; in
order to be interpreted and displayed as themselves in text, while
within the code itself, they are used for HTML tags. If malicious
content is injected into an application that escapes special characters
and that malicious content uses `<` and `>` as HTML tags, those
characters are nonetheless not interpreted as HTML tags by the browser
if they’ve been correctly escaped in the application code and in this
way the attempted attack is diverted.

The most prominent use of XSS is to steal cookies (source: OWASP
HttpOnly) and hijack user sessions, but XSS exploits have been used to
expose sensitive information, enable access to privileged services and
functionality and deliver malware.

### Types of attacks {#types-of-attacks}

There are a few methods by which XSS can be manipulated:

  Type            Origin   Description
  --------------- -------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Stored**      Server   The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.
  **Reflected**   Server   The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.
  **DOM-based**   Client   The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.
  **Mutated**              The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.

### Affected environments {#affected-environments}

The following environments are susceptible to an XSS attack:

-   Web servers
-   Application servers
-   Web application environments

### How to prevent {#how-to-prevent}

This section describes the top best practices designed to specifically
protect your code:

-   Sanitize data input in an HTTP request before reflecting it back,
    ensuring all data is validated, filtered or escaped before echoing
    anything back to the user, such as the values of query parameters
    during searches.
-   Convert special characters such as `?`, `&`, `/`, `<`, `>` and
    spaces to their respective HTML or URL encoded equivalents.
-   Give users the option to disable client-side scripts.
-   Redirect invalid requests.
-   Detect simultaneous logins, including those from two separate IP
    addresses, and invalidate those sessions.
-   Use and enforce a Content Security Policy (source: Wikipedia) to
    disable any features that might be manipulated for an XSS attack.
-   Read the documentation for any of the libraries referenced in your
    code to understand which elements allow for embedded HTML.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.3.9 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/markedjs/marked/pull/976/commits/6d1901ff71abb83aa32ca9a5ce47471382ea42a9)

-   [GitHub Issue](https://github.com/chjj/marked/issues/925)

-   [GitHub PR](https://github.com/chjj/marked/pull/958)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:marked:20170815)

Cross-site Scripting (XSS) {.card__title}
--------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Cross-site Scripting
(XSS). When mangling is disabled via option `mangle`, marked doesn't
escape target `href`. This may allow an attacker to inject arbitrary
`html-event` into resulting a tag.

For example:

    var marked = require('marked');
              marked.setOptions({
                renderer: new marked.Renderer(),
                sanitize: true,
                mangle: false
              });
              
              text = `
              <bar"onclick="alert('XSS')"@foo>
              `;
              
              console.log(marked(text));

will render:

    <p><a href="mailto:bar"onclick="alert('XSS')"@foo">bar"onclick="alert('XSS')"@foo</a></p>

Details {#details}
-------

A cross-site scripting attack occurs when the attacker tricks a
legitimate web-based application or site to accept a request as
originating from a trusted source.

This is done by escaping the context of the web application; the web
application then delivers that data to its users along with other
trusted dynamic content, without validating it. The browser unknowingly
executes malicious script on the client side (through client-side
languages; usually JavaScript or HTML) in order to perform actions that
are otherwise typically blocked by the browser’s Same Origin Policy.

ֿInjecting malicious code is the most prevalent manner by which XSS is
exploited; for this reason, escaping characters in order to prevent this
manipulation is the top method for securing code against this
vulnerability.

Escaping means that the application is coded to mark key characters, and
particularly key characters included in user input, to prevent those
characters from being interpreted in a dangerous context. For example,
in HTML, `<` can be coded as `&lt`; and `>` can be coded as `&gt`; in
order to be interpreted and displayed as themselves in text, while
within the code itself, they are used for HTML tags. If malicious
content is injected into an application that escapes special characters
and that malicious content uses `<` and `>` as HTML tags, those
characters are nonetheless not interpreted as HTML tags by the browser
if they’ve been correctly escaped in the application code and in this
way the attempted attack is diverted.

The most prominent use of XSS is to steal cookies (source: OWASP
HttpOnly) and hijack user sessions, but XSS exploits have been used to
expose sensitive information, enable access to privileged services and
functionality and deliver malware.

### Types of attacks {#types-of-attacks}

There are a few methods by which XSS can be manipulated:

  Type            Origin   Description
  --------------- -------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Stored**      Server   The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.
  **Reflected**   Server   The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.
  **DOM-based**   Client   The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.
  **Mutated**              The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.

### Affected environments {#affected-environments}

The following environments are susceptible to an XSS attack:

-   Web servers
-   Application servers
-   Web application environments

### How to prevent {#how-to-prevent}

This section describes the top best practices designed to specifically
protect your code:

-   Sanitize data input in an HTTP request before reflecting it back,
    ensuring all data is validated, filtered or escaped before echoing
    anything back to the user, such as the values of query parameters
    during searches.
-   Convert special characters such as `?`, `&`, `/`, `<`, `>` and
    spaces to their respective HTML or URL encoded equivalents.
-   Give users the option to disable client-side scripts.
-   Redirect invalid requests.
-   Detect simultaneous logins, including those from two separate IP
    addresses, and invalidate those sessions.
-   Use and enforce a Content Security Policy (source: Wikipedia) to
    disable any features that might be manipulated for an XSS attack.
-   Read the documentation for any of the libraries referenced in your
    code to understand which elements allow for embedded HTML.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.3.9 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/markedjs/marked/pull/976/commits/cb72584c5d9d32ebfdbb99e35fb9b81af2b79686)

-   [GitHub Issue](https://github.com/chjj/marked/issues/926)

-   [GitHub PR](https://github.com/chjj/marked/pull/958)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:marked:20170815-1)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS) when parsing the input markdown content (1,000
characters costs around 6 seconds matching time).

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.3.9 or higher.

References {#references}
----------

-   [GitHub Issue](https://github.com/chjj/marked/issues/937)

-   [GitHub PR](https://github.com/chjj/marked/pull/958)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:marked:20170907)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: marked
-   Introduced through: goof@1.0.1 and marked@0.3.5

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › marked@0.3.5

* * * * *

Overview {#overview}
--------

[marked](https://marked.js.org/) is a low-level compiler for parsing
markdown without caching or blocking for long periods of time.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). This can cause an impact of about 10 seconds
matching time for data 150 characters long.

Disclosure Timeline
-------------------

-   Feb 21th, 2018 - Initial Disclosure to package owner
-   Feb 21th, 2018 - Initial Response from package owner
-   Feb 26th, 2018 - Fix issued
-   Feb 27th, 2018 - Vulnerability published

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `marked` to version 0.3.18 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/markedjs/marked/pull/1083/commits/b15e42b67cec9ded8505e9d68bb8741ad7a9590d)

-   [GitHub PR](https://github.com/markedjs/marked/pull/1083)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:marked:20180225)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: mixin-deep
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › base@0.11.2 ›
    mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › base@0.11.2 ›
    mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › base@0.11.2 ›
    mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › base@0.11.2
    › mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    base@0.11.2 › mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › base@0.11.2 › mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › base@0.11.2 › mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › base@0.11.2 › mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › base@0.11.2 › mixin-deep@1.3.1
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › base@0.11.2 ›
    mixin-deep@1.3.1

* * * * *

Overview {#overview}
--------

[mixin-deep](https://www.npmjs.com/package/mixin-deep) is a package that
deeply mixes the properties of objects into the first object.

Affected versions of this package are vulnerable to Prototype Pollution.
The function `mixin-deep` could be tricked into adding or modifying
properties of `Object.prototype` using a `constructor` payload.

PoC by Snyk {#poc-by-snyk}
-----------

    const mixin = require('mixin-deep');
              const payload = '{"constructor": {"prototype": {"a0": true}}}'
              
              function check() {
                  mixin({}, JSON.parse(payload));
                  if (({})[`a0`] === true) {
                        console.log(`Vulnerable to Prototype Pollution via ${payload}`)
                }
              }
              
              check();

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `mixin-deep` to version 2.0.1, 1.3.2 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/jonschlinkert/mixin-deep/commit/8f464c8ce9761a8c9c2b3457eaeee9d404fa7af9)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-MIXINDEEP-450212)

Denial of Service (DoS) {.card__title}
-----------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: mongodb
-   Introduced through: goof@1.0.1, mongoose@4.2.4 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › mongoose@4.2.4 › mongodb@2.0.46

* * * * *

Overview {#overview}
--------

[mongodb](https://www.npmjs.com/package/mongodb) is a official MongoDB
driver for Node.js.

Affected versions of this package are vulnerable to Denial of Service
(DoS). The package fails to properly catch an exception when a
collection name is invalid and the DB does not exist, crashing the
application.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its intended and legitimate users.

Unlike other vulnerabilities, DoS attacks usually do not aim at
breaching security. Rather, they are focused on making websites and
services unavailable to genuine users resulting in downtime.

One popular Denial of Service vulnerability is DDoS (a Distributed
Denial of Service), an attack that attempts to clog network pipes to the
system by generating a large volume of traffic from many machines.

When it comes to open source libraries, DoS vulnerabilities allow
attackers to trigger such a crash or crippling of the service by using a
flaw either in the application code or from the use of open source
libraries.

Two common types of DoS vulnerabilities:

-   High CPU/Memory Consumption- An attacker sending crafted requests
    that could cause the system to take a disproportionate amount of
    time to process. For example,
    [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).

-   Crash - An attacker sending crafted requests that could cause the
    system to crash. For Example, [npm `ws` package](npm:ws:20171108)

Remediation {#remediation}
-----------

Upgrade `mongodb` to version 3.1.13 or higher.

References {#references}
----------

-   [NPM Security Advisory](https://www.npmjs.com/advisories/1203)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-MONGODB-473855)

Information Exposure {.card__title}
--------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: mongoose
-   Introduced through: goof@1.0.1 and mongoose@4.2.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › mongoose@4.2.4

* * * * *

Overview {#overview}
--------

[mongoose](https://www.npmjs.com/package/mongoose) is a Mongoose is a
MongoDB object modeling tool designed to work in an asynchronous
environment.

Affected versions of this package are vulnerable to Information
Exposure. Any query object with a `_bsontype` attribute is ignored,
allowing attackers to bypass access control.

Remediation {#remediation}
-----------

Upgrade `mongoose` to version 5.7.5 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/Automattic/mongoose/commit/f3eca5b94d822225c04e96cbeed9f095afb3c31c)

-   [GitHub Issue](https://github.com/Automattic/mongoose/issues/8222)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-MONGOOSE-472486)

Remote Memory Exposure {.card__title}
----------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: mongoose
-   Introduced through: goof@1.0.1 and mongoose@4.2.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › mongoose@4.2.4

* * * * *

Overview {#overview}
--------

A potential memory disclosure vulnerability exists in mongoose. A
`Buffer` field in a MongoDB document can be used to expose sensitive
information such as code, runtime memory and user data into MongoDB.

### Details {#details}

Initializing a `Buffer` field in a document with integer `N` creates a
`Buffer` of length `N` with non zero-ed out memory. **Example:**

    var x = new Buffer(100); // uninitialized Buffer of length 100
              // vs
              var x = new Buffer('100'); // initialized Buffer with value of '100'

Initializing a MongoDB document field in such manner will dump
uninitialized memory into MongoDB. The patch wraps `Buffer` field
initialization in mongoose by converting a `number` value `N` to array
`[N]`, initializing the `Buffer` with `N` in its binary form.

#### Proof of concept

    var mongoose = require('mongoose');
              mongoose.connect('mongodb://localhost/bufftest');
              
              // data: Buffer is not uncommon, taken straight from the docs: http://mongoosejs.com/docs/schematypes.html
              mongoose.model('Item', new mongoose.Schema({id: String, data: Buffer}));
              
              var Item = mongoose.model('Item');
              
              var sample = new Item();
              sample.id = 'item1';
              
              // This will create an uninitialized buffer of size 100
              sample.data = 100;
              sample.save(function () {
                  Item.findOne(function (err, result) {
                      // Print out the data (exposed memory)
                      console.log(result.data.toString('ascii'))
                      mongoose.connection.db.dropDatabase(); // Clean up everything
                      process.exit();
                  });
              });

Remediation {#remediation}
-----------

Upgrade `mongoose` to version \>= 3.8.39 or \>= 4.3.6.

If a direct dependency update is not possible, use
[`snyk wizard`](https://snyk.io/docs/using-snyk#wizard) to patch this
vulnerability.

References {#references}
----------

-   [GitHub Issue](https://github.com/Automattic/mongoose/issues/3764)
-   [Blog: Node Buffer API
    fix](https://github.com/ChALkeR/notes/blob/master/Lets-fix-Buffer-API.md#previous-materials)
-   [Blog: Information about
    Buffer](https://github.com/ChALkeR/notes/blob/master/Buffer-knows-everything.md)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:mongoose:20160116)

Prototype Pollution {.card__title}
-------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: set-value
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › base@0.11.2
    › cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    base@0.11.2 › cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › set-value@2.0.0
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › braces@2.3.2 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › nanomatch@1.2.9 › snapdragon@0.8.2 › base@0.11.2
    › cache-base@1.0.1 › union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › snapdragon@0.8.2 ›
    base@0.11.2 › cache-base@1.0.1 › union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › braces@2.3.2 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 ›
    union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    micromatch@3.1.10 › extglob@2.0.4 › expand-brackets@2.1.4 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 ›
    union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 ›
    union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › nanomatch@1.2.9 ›
    snapdragon@0.8.2 › base@0.11.2 › cache-base@1.0.1 ›
    union-value@1.0.0 › set-value@0.4.3
-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    test-exclude@4.2.1 › micromatch@3.1.10 › extglob@2.0.4 ›
    expand-brackets@2.1.4 › snapdragon@0.8.2 › base@0.11.2 ›
    cache-base@1.0.1 › union-value@1.0.0 › set-value@0.4.3

* * * * *

Overview {#overview}
--------

[set-value](https://www.npmjs.com/package/set-value) is a package that
creates nested values and any intermediaries using dot notation
('a.b.c') paths.

Affected versions of this package are vulnerable to Prototype Pollution.
The function `set-value` could be tricked into adding or modifying
properties of `Object.prototype` using any of the `constructor`,
`prototype` and `_proto_` payloads.

PoC by Snyk {#poc-by-snyk}
-----------

    const setFn = require('set-value');
              const paths = [
                'constructor.prototype.a0',
                '__proto__.a1',
              ];
              
              function check() {
                for (const p of paths) {
                    setFn({}, p, true);
                }
                for (let i = 0; i < paths.length; i++) {
                    if (({})[`a${i}`] === true) {
                        console.log(`Yes with ${paths[i]}`);
                    }
                }
              }
              
              check();
              

Details {#details}
-------

Prototype Pollution is a vulnerability affecting JavaScript. Prototype
Pollution refers to the ability to inject properties into existing
JavaScript language construct prototypes, such as objects. JavaScript
allows all Object attributes to be altered, including their magical
attributes such as `_proto_`, `constructor` and `prototype`. An attacker
manipulates these attributes to overwrite, or pollute, a JavaScript
application object prototype of the base object by injecting other
values. Properties on the `Object.prototype` are then inherited by all
the JavaScript objects through the prototype chain. When that happens,
this leads to either denial of service by triggering JavaScript
exceptions, or it tampers with the application source code to force the
code path that the attacker injects, thereby leading to remote code
execution.

There are two main ways in which the pollution of prototypes occurs:

-   Unsafe `Object` recursive merge

-   Property definition by path

### Unsafe Object recursive merge {#unsafe-object-recursive-merge}

The logic of a vulnerable recursive merge function follows the following
high-level model:

    merge (target, source)
              
                foreach property of source
              
                  if property exists and is an object on both the target and the source
              
                    merge(target[property], source[property])
              
                  else
              
                    target[property] = source[property]

\

When the source object contains a property named `_proto_` defined with
`Object.defineProperty()` , the condition that checks if the property
exists and is an object on both the target and the source passes and the
merge recurses with the target, being the prototype of `Object` and the
source of `Object` as defined by the attacker. Properties are then
copied on the `Object` prototype.

Clone operations are a special sub-class of unsafe recursive merges,
which occur when a recursive merge is conducted on an empty object:
`merge({},source)`.

`lodash` and `Hoek` are examples of libraries susceptible to recursive
merge attacks.

### Property definition by path {#property-definition-by-path}

There are a few JavaScript libraries that use an API to define property
values on an object based on a given path. The function that is
generally affected contains this signature:
`theFunction(object, path, value)`

If the attacker can control the value of “path”, they can set this value
to `_proto_.myValue`. `myValue` is then assigned to the prototype of the
class of the object.

Types of attacks {#types-of-attacks}
----------------

There are a few methods by which Prototype Pollution can be manipulated:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Type                          Origin   Short description
  ----------------------------- -------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Denial of service (DoS)**   Client   This is the most likely attack. \
                                         DoS occurs when `Object` holds generic functions that are implicitly called for various operations (for example, `toString` and `valueOf`). \
                                          The attacker pollutes `Object.prototype.someattr` and alters its state to an unexpected value such as `Int` or `Object`. In this case, the code fails and is likely to cause a denial of service. \
                                         **For example:** if an attacker pollutes `Object.prototype.toString` by defining it as an integer, if the codebase at any point was reliant on `someobject.toString()` it would fail.

  **Remote Code Execution**     Client   Remote code execution is generally only possible in cases where the codebase evaluates a specific attribute of an object, and then executes that evaluation.\
                                         **For example:** `eval(someobject.someattr)`. In this case, if the attacker pollutes `Object.prototype.someattr` they are likely to be able to leverage this in order to execute code.

  **Property Injection**        Client   The attacker pollutes properties that the codebase relies on for their informative value, including security properties such as cookies or tokens.\
                                          **For example:** if a codebase checks privileges for `someuser.isAdmin`, then when the attacker pollutes `Object.prototype.isAdmin` and sets it to equal `true`, they can then achieve admin privileges.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Affected environments {#affected-environments}
---------------------

The following environments are susceptible to a Prototype Pollution
attack:

-   Application server

-   Web server

How to prevent {#how-to-prevent}
--------------

1.  Freeze the prototype— use `Object.freeze (Object.prototype)`.

2.  Require schema validation of JSON input.

3.  Avoid using unsafe recursive merge functions.

4.  Consider using objects without prototypes (for example,
    `Object.create(null)`), breaking the prototype chain and preventing
    pollution.

5.  As a best practice use `Map` instead of `Object`.

### For more information on this vulnerability type: {#for-more-information-on-this-vulnerability-type}

[Arteau, Oliver. “JavaScript prototype pollution attack in NodeJS
application.” GitHub, 26 May
2018](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)

Remediation {#remediation}
-----------

Upgrade `set-value` to version 2.0.1, 3.0.1 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/jonschlinkert/set-value/commit/95e9d9923f8a8b4a01da1ea138fcc39ec7b6b15f)

-   [NPM Security Advisory](https://nodesecurity.io/advisories/1012)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/SNYK-JS-SETVALUE-450213)

Arbitrary File Write via Archive Extraction (Zip Slip) {.card__title}
------------------------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: adm-zip
-   Introduced through: goof@1.0.1 and adm-zip@0.4.7

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › adm-zip@0.4.7

* * * * *

Overview {#overview}
--------

[adm-zip](https://www.npmjs.com/package/adm-zip) is a JavaScript
implementation for zip data compression for NodeJS.

Affected versions of this package are vulnerable to Arbitrary File Write
via Archive Extraction (Zip Slip).

Details {#details}
-------

It is exploited using a specially crafted zip archive, that holds path
traversal filenames. When exploited, a filename in a malicious archive
is concatenated to the target extraction directory, which results in the
final path ending up outside of the target folder. For instance, a zip
may hold a file with a "../../file.exe" location and thus break out of
the target folder. If an executable or a configuration file is
overwritten with a file containing malicious code, the problem can turn
into an arbitrary code execution issue quite easily.

The following is an example of a zip archive with one benign file and
one malicious file. Extracting the malicous file will result in
traversing out of the target folder, ending up in `/root/.ssh/`
overwriting the `authorized_keys` file:

              +2018-04-15 22:04:29 ..... 19 19 good.txt
              
              +2018-04-15 22:04:42 ..... 20 20 ../../../../../../root/.ssh/authorized_keys
              

Remediation {#remediation}
-----------

Upgrade `adm-zip` to version 0.4.11 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/cthackers/adm-zip/commit/d01fa8c80c3a5fcf5ce1eda82d96600c62910d3f)

-   [GitHub
    Commit](https://github.com/cthackers/adm-zip/pull/212/commits/6f4dfeb9a2166e93207443879988f97d88a37cde)

-   [Hackerone Report](https://hackerone.com/reports/362118)

-   [Zip Slip Advisory](https://github.com/snyk/zip-slip-vulnerability)

-   [Zip Slip Advisory](https://snyk.io/research/zip-slip-vulnerability)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:adm-zip:20180415)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

low severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: debug
-   Introduced through: goof@1.0.1, express@4.12.4 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › express@4.12.4 › debug@2.2.0
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    finalhandler@0.3.6 › debug@2.2.0
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › send@0.12.3 ›
    debug@2.2.0
-   *Introduced through*: goof@1.0.1 › mongoose@4.2.4 › mquery@1.6.3 ›
    debug@2.2.0
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    serve-static@1.9.3 › send@0.12.3 › debug@2.2.0

* * * * *

Overview {#overview}
--------

[`debug`](https://www.npmjs.com/package/debug) is a JavaScript debugging
utility modelled after Node.js core's debugging technique..

`debug` uses
[printf-style](https://wikipedia.org/wiki/Printf_format_string)
formatting. Affected versions of this package are vulnerable to Regular
expression Denial of Service (ReDoS) attacks via the the `%o` formatter
(Pretty-print an Object all on a single line). It used a regular
expression (`/\s*\n\s*/g`) in order to strip whitespaces and replace
newlines with spaces, in order to join the data into a single line. This
can cause a very low impact of about 2 seconds matching time for data
50k characters long.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `debug` to version 2.6.9, 3.1.0 or higher.

References {#references}
----------

-   [GitHub Issue](https://github.com/visionmedia/debug/issues/501)
-   [GitHub PR](https://github.com/visionmedia/debug/pull/504)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:debug:20170905)

Code Injection {.card__title}
--------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: dustjs-linkedin
-   Introduced through: goof@1.0.1 and dustjs-linkedin@2.5.0

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › dustjs-linkedin@2.5.0

* * * * *

Overview {#overview}
--------

[dustjs-linkedin](https://www.npmjs.com/package/dustjs-linkedin) is a
Javascript templating engine designed to run asynchronously on both the
server and the browser.

Affected versions of this package are vulnerable to Code Injection.
Dust.js uses Javascript's `eval()` function to evaluate the "if"
statement conditions. The input to the function is sanitized by escaping
all potentially dangerous characters.

However, if the variable passed in is an array, no escaping is applied,
exposing an easy path to code injection. The risk of exploit is
especially high given the fact `express`, `koa` and many other Node.js
servers allow users to force a query parameter to be an array using the
`param[]=value` notation.

Remediation {#remediation}
-----------

Upgrade `dustjs-linkedin` to version 2.6.0 or higher.

References {#references}
----------

-   [Artsploit
    Blog](https://artsploit.blogspot.co.il/2016/08/pprce2.html)

-   [GitHub
    Commit](https://github.com/linkedin/dustjs/pull/534/commits/884be3bb3a34a843e6fb411100088e9b02326bd4)

-   [GitHub Issue](https://github.com/linkedin/dustjs/issues/741)

-   [GitHub PR](https://github.com/linkedin/dustjs/pull/534)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:dustjs-linkedin:20160819)

Arbitrary Code Execution {.card__title}
------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: ejs
-   Introduced through: goof@1.0.1 and ejs@1.0.0

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › ejs@1.0.0
-   *Introduced through*: goof@1.0.1 › ejs-locals@1.0.2 › ejs@0.8.8

* * * * *

Overview {#overview}
--------

[`ejs`](https://www.npmjs.com/package/ejs) is a popular JavaScript
templating engine. Affected versions of the package are vulnerable to
*Remote Code Execution* by letting the attacker under certain conditions
control the source folder from which the engine renders include files.
You can read more about this vulnerability on the [Snyk
blog](https://snyk.io/blog/fixing-ejs-rce-vuln).

There's also a [Cross-site
Scripting](https://snyk.io/vuln/npm:ejs:20161130) & [Denial of
Service](https://snyk.io/vuln/npm:ejs:20161130-1) vulnerabilities caused
by the same behaviour.

Details {#details}
-------

`ejs` provides a few different options for you to render a template, two
being very similar: `ejs.render()` and `ejs.renderFile()`. The only
difference being that `render` expects a string to be used for the
template and `renderFile` expects a path to a template file.

Both functions can be invoked in two ways. The first is calling them
with `template`, `data`, and `options`:

    ejs.render(str, data, options);
              
              ejs.renderFile(filename, data, options, callback)

The second way would be by calling only the `template` and `data`, while
`ejs` lets the `options` be passed as part of the `data`:

    ejs.render(str, dataAndOptions);
              
              ejs.renderFile(filename, dataAndOptions, callback)

If used with a variable list supplied by the user (e.g. by reading it
from the URI with `qs` or equivalent), an attacker can control `ejs`
options. This includes the `root` option, which allows changing the
project root for includes with an absolute path.

    ejs.renderFile('my-template', {root:'/bad/root/'}, callback);

By passing along the root directive in the line above, any includes
would now be pulled from `/bad/root` instead of the path intended. This
allows the attacker to take control of the root directory for included
scripts and divert it to a library under his control, thus leading to
remote code execution.

The
[fix](https://github.com/mde/ejs/commit/3d447c5a335844b25faec04b1132dbc721f9c8f6)
introduced in version `2.5.3` blacklisted `root` options from options
passed via the `data` object.

Disclosure Timeline {#disclosure-timeline}
-------------------

-   November 27th, 2016 - Reported the issue to package owner.
-   November 27th, 2016 - Issue acknowledged by package owner.
-   November 28th, 2016 - Issue fixed and version `2.5.3` released.

Remediation {#remediation}
-----------

The vulnerability can be resolved by either using the GitHub integration
to [generate a pull-request](https://snyk.io/org/projects) from your
dashboard or by running `snyk wizard` from the command-line interface.
Otherwise, Upgrade `ejs` to version `2.5.3` or higher.

References {#references}
----------

-   [Snyk Blog](https://snyk.io/blog/fixing-ejs-rce-vuln)
-   [Fix
    commit](https://github.com/mde/ejs/commit/3d447c5a335844b25faec04b1132dbc721f9c8f6)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:ejs:20161128)

Cross-site Scripting (XSS) {.card__title}
--------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: ejs
-   Introduced through: goof@1.0.1 and ejs@1.0.0

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › ejs@1.0.0
-   *Introduced through*: goof@1.0.1 › ejs-locals@1.0.2 › ejs@0.8.8

* * * * *

Overview {#overview}
--------

[`ejs`](https://www.npmjs.com/package/ejs) is a popular JavaScript
templating engine. Affected versions of the package are vulnerable to
*Cross-site Scripting* by letting the attacker under certain conditions
control and override the `filename` option causing it to render the
value as is, without escaping it. You can read more about this
vulnerability on the [Snyk
blog](https://snyk.io/blog/fixing-ejs-rce-vuln).

There's also a [Remote Code
Execution](https://snyk.io/vuln/npm:ejs:20161128) & [Denial of
Service](https://snyk.io/vuln/npm:ejs:20161130-1) vulnerabilities caused
by the same behaviour.

Details {#details}
-------

`ejs` provides a few different options for you to render a template, two
being very similar: `ejs.render()` and `ejs.renderFile()`. The only
difference being that `render` expects a string to be used for the
template and `renderFile` expects a path to a template file.

Both functions can be invoked in two ways. The first is calling them
with `template`, `data`, and `options`:

    ejs.render(str, data, options);
              
              ejs.renderFile(filename, data, options, callback)

The second way would be by calling only the `template` and `data`, while
`ejs` lets the `options` be passed as part of the `data`:

    ejs.render(str, dataAndOptions);
              
              ejs.renderFile(filename, dataAndOptions, callback)

If used with a variable list supplied by the user (e.g. by reading it
from the URI with `qs` or equivalent), an attacker can control `ejs`
options. This includes the `filename` option, which will be rendered as
is when an error occurs during rendering.

    ejs.renderFile('my-template', {filename:'<script>alert(1)</script>'}, callback);

The
[fix](https://github.com/mde/ejs/commit/49264e0037e313a0a3e033450b5c184112516d8f)
introduced in version `2.5.3` blacklisted `root` options from options
passed via the `data` object.

Disclosure Timeline {#disclosure-timeline}
-------------------

-   November 28th, 2016 - Reported the issue to package owner.
-   November 28th, 2016 - Issue acknowledged by package owner.
-   December 06th, 2016 - Issue fixed and version `2.5.5` released.

Remediation {#remediation}
-----------

The vulnerability can be resolved by either using the GitHub integration
to [generate a pull-request](https://snyk.io/org/projects) from your
dashboard or by running `snyk wizard` from the command-line interface.
Otherwise, Upgrade `ejs` to version `2.5.5` or higher.

References {#references}
----------

-   [Snyk Blog](https://snyk.io/blog/fixing-ejs-rce-vuln)
-   [Fix
    commit](https://github.com/mde/ejs/commit/49264e0037e313a0a3e033450b5c184112516d8f)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:ejs:20161130)

Denial of Service (DoS) {.card__title}
-----------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: ejs
-   Introduced through: goof@1.0.1 and ejs@1.0.0

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › ejs@1.0.0
-   *Introduced through*: goof@1.0.1 › ejs-locals@1.0.2 › ejs@0.8.8

* * * * *

Overview {#overview}
--------

[`ejs`](https://www.npmjs.com/package/ejs) is a popular JavaScript
templating engine. Affected versions of the package are vulnerable to
*Denial of Service* by letting the attacker under certain conditions
control and override the `localNames` option causing it to crash. You
can read more about this vulnerability on the [Snyk
blog](https://snyk.io/blog/fixing-ejs-rce-vuln).

There's also a [Remote Code
Execution](https://snyk.io/vuln/npm:ejs:20161128) & [Cross-site
Scripting](https://snyk.io/vuln/npm:ejs:20161130) vulnerabilities caused
by the same behaviour.

Details {#details}
-------

`ejs` provides a few different options for you to render a template, two
being very similar: `ejs.render()` and `ejs.renderFile()`. The only
difference being that `render` expects a string to be used for the
template and `renderFile` expects a path to a template file.

Both functions can be invoked in two ways. The first is calling them
with `template`, `data`, and `options`:

    ejs.render(str, data, options);
              
              ejs.renderFile(filename, data, options, callback)

The second way would be by calling only the `template` and `data`, while
`ejs` lets the `options` be passed as part of the `data`:

    ejs.render(str, dataAndOptions);
              
              ejs.renderFile(filename, dataAndOptions, callback)

If used with a variable list supplied by the user (e.g. by reading it
from the URI with `qs` or equivalent), an attacker can control `ejs`
options. This includes the `localNames` option, which will cause the
renderer to crash.

    ejs.renderFile('my-template', {localNames:'try'}, callback);

The
[fix](https://github.com/mde/ejs/commit/49264e0037e313a0a3e033450b5c184112516d8f)
introduced in version `2.5.3` blacklisted `root` options from options
passed via the `data` object.

Disclosure Timeline {#disclosure-timeline}
-------------------

-   November 28th, 2016 - Reported the issue to package owner.
-   November 28th, 2016 - Issue acknowledged by package owner.
-   December 06th, 2016 - Issue fixed and version `2.5.5` released.

Remediation {#remediation}
-----------

The vulnerability can be resolved by either using the GitHub integration
to [generate a pull-request](https://snyk.io/org/projects) from your
dashboard or by running `snyk wizard` from the command-line interface.
Otherwise, Upgrade `ejs` to version `2.5.5` or higher.

References {#references}
----------

-   [Snyk Blog](https://snyk.io/blog/fixing-ejs-rce-vuln)
-   [Fix
    commit](https://github.com/mde/ejs/commit/49264e0037e313a0a3e033450b5c184112516d8f)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:ejs:20161130-1)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: fresh
-   Introduced through: goof@1.0.1, express@4.12.4 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › express@4.12.4 › fresh@0.2.4
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › send@0.12.3 ›
    fresh@0.2.4
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    serve-static@1.9.3 › send@0.12.3 › fresh@0.2.4

* * * * *

Overview {#overview}
--------

[`fresh`](https://www.npmjs.com/package/fresh) is HTTP response
freshness testing.

Affected versions of this package are vulnerable to Regular expression
Denial of Service (ReDoS) attacks. A Regular Expression (`/ *, */`) was
used for parsing HTTP headers and take about 2 seconds matching time for
50k characters.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `fresh` to version 0.5.2 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/jshttp/fresh/commit/21a0f0c2a5f447e0d40bc16be0c23fa98a7b46ec)
-   [GitHub Issue](https://github.com/jshttp/fresh/issues/24)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:fresh:20170908)

Denial of Service (DoS) {.card__title}
-----------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: mem
-   Introduced through: goof@1.0.1, tap@11.1.5 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › tap@11.1.5 › nyc@11.9.0 ›
    yargs@11.1.0 › os-locale@2.1.0 › mem@1.1.0

* * * * *

Overview {#overview}
--------

[mem](https://www.npmjs.com/package/mem) is an optimization used to
speed up consecutive function calls by caching the result of calls with
identical input.

Affected versions of this package are vulnerable to Denial of Service
(DoS). Old results were deleted from the cache and could cause a memory
leak.

details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its intended and legitimate users.

Unlike other vulnerabilities, DoS attacks usually do not aim at
breaching security. Rather, they are focused on making websites and
services unavailable to genuine users resulting in downtime.

One popular Denial of Service vulnerability is DDoS (a Distributed
Denial of Service), an attack that attempts to clog network pipes to the
system by generating a large volume of traffic from many machines.

When it comes to open source libraries, DoS vulnerabilities allow
attackers to trigger such a crash or crippling of the service by using a
flaw either in the application code or from the use of open source
libraries.

Two common types of DoS vulnerabilities:

-   High CPU/Memory Consumption- An attacker sending crafted requests
    that could cause the system to take a disproportionate amount of
    time to process. For example,
    [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).

-   Crash - An attacker sending crafted requests that could cause the
    system to crash. For Example, [npm `ws` package](npm:ws:20171108)

Remediation {#remediation}
-----------

Upgrade mem to version 4.0.0 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/sindresorhus/mem/commit/da4e4398cb27b602de3bd55f746efa9b4a31702b)

-   [GitHub Issue](https://github.com/sindresorhus/mem/issues/14)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:mem:20180117)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

low severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: mime
-   Introduced through: goof@1.0.1, express@4.12.4 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › express@4.12.4 › send@0.12.3 ›
    mime@1.3.4
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    serve-static@1.9.3 › send@0.12.3 › mime@1.3.4
-   *Introduced through*: goof@1.0.1 › st@0.2.4 › mime@1.2.11

* * * * *

Overview {#overview}
--------

[mime](https://www.npmjs.com/package/mime) is a comprehensive, compact
MIME type module.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). It uses regex the following regex
`/.*[\.\/\\]/` in its lookup, which can cause a slowdown of 2 seconds
for 50k characters.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `mime` to version 1.4.1, 2.0.3 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/broofa/node-mime/commit/1df903fdeb9ae7eaa048795b8d580ce2c98f40b0)

-   [GitHub
    Commit](https://github.com/broofa/node-mime/commit/855d0c4b8b22e4a80b9401a81f2872058eae274d)

-   [GitHub Issue](https://github.com/broofa/node-mime/issues/167)

-   [NPM Security Advisory](https://www.npmjs.com/advisories/535)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:mime:20170907)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: moment
-   Introduced through: goof@1.0.1 and moment@2.15.1

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › moment@2.15.1

* * * * *

Overview {#overview}
--------

[`moment`](https://www.npmjs.com/package/moment) is a lightweight
JavaScript date library for parsing, validating, manipulating, and
formatting dates.

Affected versions of the package are vulnerable to Regular Expression
Denial of Service (ReDoS) attacks for any locale that has separate
format and standalone options and `format` input can be controlled by
the user.

An attacker can provide a specially crafted input to the `format`
function, which nearly matches the pattern being matched. This will
cause the regular expression matching to take a long time, all the while
occupying the event loop and preventing it from processing other
requests and making the server unavailable (a Denial of Service attack).

Disclosure Timeline {#disclosure-timeline}
-------------------

-   October 19th, 2016 - Reported the issue to package owner.
-   October 19th, 2016 - Issue acknowledged by package owner.
-   October 24th, 2016 - Issue fixed and version `2.15.2` released.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

References {#references}
----------

-   [Proof of
    concept](https://gist.github.com/grnd/50192ce22681848a7de812d95241b7fc)
-   [Fix
    commit](https://github.com/moment/moment/commit/663f33e333212b3800b63592cd8e237ac8fabdb9)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:moment:20161019)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

low severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: moment
-   Introduced through: goof@1.0.1 and moment@2.15.1

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › moment@2.15.1

* * * * *

Overview {#overview}
--------

[moment](https://www.npmjs.com/package/moment) is a lightweight
JavaScript date library for parsing, validating, manipulating, and
formatting dates.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). It used a regular expression
(`/[0-9]*['a-z\u00A0-\u05FF\u0700-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]+|[\u0600-\u06FF\/]+(\s*?[\u0600-\u06FF]+){1,2}/i`)
in order to parse dates specified as strings. This can cause a very low
impact of about 2 seconds matching time for data 50k characters long.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `moment` to version 2.19.3 or higher.

References {#references}
----------

-   [GitHub Issue](https://github.com/moment/moment/issues/4163)

-   [GitHub PR](https://github.com/moment/moment/pull/4326)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:moment:20170905)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: ms
-   Introduced through: goof@1.0.1, humanize-ms@1.0.1 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › humanize-ms@1.0.1 › ms@0.6.2

* * * * *

Overview {#overview}
--------

[ms](https://www.npmjs.com/package/ms) is a tiny milisecond conversion
utility.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS) attack when converting a time period string
(i.e. `"2 days"`, `"1h"`) into a milliseconds integer. A malicious user
could pass extremely long strings to `ms()`, causing the server to take
a long time to process, subsequently blocking the event loop for that
extended period.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `ms` to version 0.7.1 or higher.

References {#references}
----------

-   [OSS security
    Advisory](https://www.openwall.com/lists/oss-security/2016/04/20/11)

-   [OWASP -
    ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS)

-   [Security Focus](https://www.securityfocus.com/bid/96389)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:ms:20151024)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

low severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: ms
-   Introduced through: goof@1.0.1, mongoose@4.2.4 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › mongoose@4.2.4 › ms@0.7.1
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › debug@2.2.0 ›
    ms@0.7.1
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › send@0.12.3 ›
    ms@0.7.1
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    finalhandler@0.3.6 › debug@2.2.0 › ms@0.7.1
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › send@0.12.3 ›
    debug@2.2.0 › ms@0.7.1
-   *Introduced through*: goof@1.0.1 › mongoose@4.2.4 › mquery@1.6.3 ›
    debug@2.2.0 › ms@0.7.1
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    serve-static@1.9.3 › send@0.12.3 › ms@0.7.1
-   *Introduced through*: goof@1.0.1 › express@4.12.4 ›
    serve-static@1.9.3 › send@0.12.3 › debug@2.2.0 › ms@0.7.1
-   *Introduced through*: goof@1.0.1 › ms@0.7.3

* * * * *

Overview {#overview}
--------

[`ms`](https://www.npmjs.com/package/ms) is a tiny millisecond
conversion utility.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS) due to an incomplete fix for previously
reported vulnerability
[npm:ms:20151024](https://snyk.io/vuln/npm:ms:20151024). The fix limited
the length of accepted input string to 10,000 characters, and turned to
be insufficient making it possible to block the event loop for 0.3
seconds (on a typical laptop) with a specially crafted string passed to
`ms()` function.

*Proof of concept*

    ms = require('ms');
              ms('1'.repeat(9998) + 'Q') // Takes about ~0.3s

**Note:** Snyk's patch for this vulnerability limits input length to 100
characters. This new limit was deemed to be a breaking change by the
author. Based on user feedback, we believe the risk of breakage is
*very* low, while the value to your security is much greater, and
therefore opted to still capture this change in a patch for earlier
versions as well. Whenever patching security issues, we always suggest
to run tests on your code to validate that nothing has been broken.

For more information on `Regular Expression Denial of Service (ReDoS)`
attacks, go to our
[blog](https://snyk.io/blog/redos-and-catastrophic-backtracking/).

Disclosure Timeline {#disclosure-timeline}
-------------------

-   Feb 9th, 2017 - Reported the issue to package owner.
-   Feb 11th, 2017 - Issue acknowledged by package owner.
-   April 12th, 2017 - Fix PR opened by Snyk Security Team.
-   May 15th, 2017 - Vulnerability published.
-   May 16th, 2017 - Issue fixed and version `2.0.0` released.
-   May 21th, 2017 - Patches released for versions `>=0.7.1, <=1.0.0`.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `ms` to version 2.0.0 or higher.

References {#references}
----------

-   [GitHub PR](https://github.com/zeit/ms/pull/89)
-   [GitHub
    Commit](https://github.com/zeit/ms/pull/89/commits/305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:ms:20170412)

Regular Expression Denial of Service (DoS) {.card__title}
------------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: negotiator
-   Introduced through: goof@1.0.1, errorhandler@1.2.0 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › errorhandler@1.2.0 ›
    accepts@1.1.4 › negotiator@0.4.9
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › accepts@1.2.13 ›
    negotiator@0.5.3
-   *Introduced through*: goof@1.0.1 › st@0.2.4 › negotiator@0.2.8

* * * * *

Overview {#overview}
--------

[negotiator](https://npmjs.org/package/negotiator) is an HTTP content
negotiator for Node.js.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (DoS) when parsing `Accept-Language` http header.

Details {#details}
-------

Denial of Service (DoS) describes a family of attacks, all aimed at
making a system inaccessible to its original and legitimate users. There
are many types of DoS attacks, ranging from trying to clog the network
pipes to the system by generating a large volume of traffic from many
machines (a Distributed Denial of Service - DDoS - attack) to sending
crafted requests that cause a system to crash or take a disproportional
amount of time to process.

The Regular expression Denial of Service (ReDoS) is a type of Denial of
Service attack. Regular expressions are incredibly powerful, but they
aren't very intuitive and can ultimately end up making it easy for
attackers to take your site down.

Let’s take the following regular expression as an example:

    regex = /A(B|C+)+D/

This regular expression accomplishes the following:

-   `A` The string must start with the letter 'A'
-   `(B|C+)+` The string must then follow the letter A with either the
    letter 'B' or some number of occurrences of the letter 'C' (the `+`
    matches one or more times). The `+` at the end of this section
    states that we can look for one or more matches of this section.
-   `D` Finally, we ensure this section of the string ends with a 'D'

The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD`
and `ACCCCCD`

It most cases, it doesn't take very long for a regex engine to find a
match:

    $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'
              0.04s user 0.01s system 95% cpu 0.052 total
              
              $ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'
              1.79s user 0.02s system 99% cpu 1.812 total

The entire process of testing it against a 30 characters long string
takes around \~52ms. But when given an invalid string, it takes nearly
two seconds to complete the test, over ten times as long as it took to
test a valid string. The dramatic difference is due to the way regular
expressions get evaluated.

Most Regex engines will work very similarly (with minor differences).
The engine will match the first possible way to accept the current
character and proceed to the next one. If it then fails to match the
next one, it will backtrack and see if there was another way to digest
the previous character. If it goes too far down the rabbit hole only to
find out the string doesn’t match in the end, and if many characters
have multiple valid regex paths, the number of backtracking steps can
become very large, resulting in what is known as *catastrophic
backtracking*.

Let's look at how our expression runs into this problem, using a shorter
string: "ACCCX". While it seems fairly straightforward, there are still
four different ways that the engine could match those three C's:

1.  CCC
2.  CC+C
3.  C+CC
4.  C+C+C.

The engine has to try each of those combinations to see if any of them
potentially match against the expression. When you combine that with the
other steps the engine must take, we can use [RegEx 101
debugger](https://regex101.com/debugger) to see the engine has to take a
total of 38 steps before it can determine the string doesn't match.

From there, the number of steps the engine must use to validate a string
just continues to grow.

  String             Number of C's   Number of steps
  ------------------ --------------- -----------------
  ACCCX              3               38
  ACCCCX             4               71
  ACCCCCX            5               136
  ACCCCCCCCCCCCCCX   14              65,553

By the time the string includes 14 C's, the engine has to take over
65,000 steps just to see if the string is valid. These extreme
situations can cause them to work very slowly (exponentially related to
input size, as shown above), allowing an attacker to exploit this and
can cause the service to excessively consume CPU, resulting in a Denial
of Service.

Remediation {#remediation}
-----------

Upgrade `negotiator` to version 0.6.1 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/jshttp/negotiator/commit/26a05ec15cf7d1fa56000d66ebe9c9a1a62cb75c)

-   [OSWAP
    Advisory](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:negotiator:20160616)

Uninitialized Memory Exposure {.card__title}
-----------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: npmconf
-   Introduced through: goof@1.0.1 and npmconf@0.0.24

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › npmconf@0.0.24

* * * * *

Overview {#overview}
--------

[npmconf](https://www.npmjs.com/package/npmconf) is a package to
reintegrate directly into npm.

Affected versions of this package are vulnerable to Uninitialized Memory
Exposure. It allocates and writes to disk uninitialized memory content
when a typed number is passed as input.

**Note** `npmconf` is deprecated and should not be used. **Note** This
is vulnerable only for Node \<=4

Details {#details}
-------

The Buffer class on Node.js is a mutable array of binary data, and can
be initialized with a string, array or number.

    const buf1 = new Buffer([1,2,3]);
              // creates a buffer containing [01, 02, 03]
              const buf2 = new Buffer('test');
              // creates a buffer containing ASCII bytes [74, 65, 73, 74]
              const buf3 = new Buffer(10);
              // creates a buffer of length 10

The first two variants simply create a binary representation of the
value it received. The last one, however, pre-allocates a buffer of the
specified size, making it a useful buffer, especially when reading data
from a stream. When using the number constructor of Buffer, it will
allocate the memory, but will not fill it with zeros. Instead, the
allocated buffer will hold whatever was in memory at the time. If the
buffer is not `zeroed` by using `buf.fill(0)`, it may leak sensitive
information like keys, source code, and system info.

Remediation {#remediation}
-----------

Upgrade `npmconf` to version 2.1.3 or higher.

References {#references}
----------

-   [HAckerOne Report](https://hackerone.com/reports/320269)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:npmconf:20180512)

Prototype Override Protection Bypass {.card__title}
------------------------------------

high severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: qs
-   Introduced through: goof@1.0.1, body-parser@1.9.0 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › body-parser@1.9.0 › qs@2.2.4
-   *Introduced through*: goof@1.0.1 › express@4.12.4 › qs@2.4.2

* * * * *

Overview {#overview}
--------

[qs](https://www.npmjs.com/package/qs) is a querystring parser that
supports nesting and arrays, with a depth limit.

Affected versions of this package are vulnerable to Prototype Override
Protection Bypass. By default `qs` protects against attacks that attempt
to overwrite an object's existing prototype properties, such as
`toString()`, `hasOwnProperty()`,etc.

From [`qs` documentation](https://github.com/ljharb/qs):

> By default parameters that would overwrite properties on the object
> prototype are ignored, if you wish to keep the data from those fields
> either use plainObjects as mentioned above, or set allowPrototypes to
> true which will allow user input to overwrite those properties.
> WARNING It is generally a bad idea to enable this option as it can
> cause problems when attempting to use the properties that have been
> overwritten. Always be careful with this option.

Overwriting these properties can impact application logic, potentially
allowing attackers to work around security controls, modify data, make
the application unstable and more.

In versions of the package affected by this vulnerability, it is
possible to circumvent this protection and overwrite prototype
properties and functions by prefixing the name of the parameter with `[`
or `]`. e.g. `qs.parse("]=toString")` will return `{toString = true}`,
as a result, calling `toString()` on the object will throw an exception.

**Example:**

    qs.parse('toString=foo', { allowPrototypes: false })
              // {}
              
              qs.parse("]=toString", { allowPrototypes: false })
              // {toString = true} <== prototype overwritten

For more information, you can check out our
[blog](https://snyk.io/blog/high-severity-vulnerability-qs/).

Disclosure Timeline {#disclosure-timeline}
-------------------

-   February 13th, 2017 - Reported the issue to package owner.
-   February 13th, 2017 - Issue acknowledged by package owner.
-   February 16th, 2017 - Partial fix released in versions `6.0.3`,
    `6.1.1`, `6.2.2`, `6.3.1`.
-   March 6th, 2017 - Final fix released in versions `6.4.0`,`6.3.2`,
    `6.2.3`, `6.1.2` and `6.0.4`

Remediation {#remediation}
-----------

Upgrade `qs` to version 6.0.4, 6.1.2, 6.2.3, 6.3.2 or higher.

References {#references}
----------

-   [GitHub
    Commit](https://github.com/ljharb/qs/commit/beade029171b8cef9cee0d03ebe577e2dd84976d)

-   [GitHub Issue](https://github.com/ljharb/qs/issues/200)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:qs:20170213)

Regular Expression Denial of Service (ReDoS) {.card__title}
--------------------------------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: semver
-   Introduced through: goof@1.0.1, npmconf@0.0.24 and others

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › npmconf@0.0.24 › semver@1.1.4

* * * * *

Overview {#overview}
--------

[semver](https://github.com/npm/node-semver) is a semantic version
parser used by npm.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS).

Overview {#overview-1}
--------

[npm](https://github.com/npm/npm) is a package manager for javascript.

Affected versions of this package are vulnerable to Regular Expression
Denial of Service (ReDoS). The semver module uses regular expressions
when parsing a version string. For a carefully crafted input, the time
it takes to process these regular expressions is not linear to the
length of the input. Since the semver module did not enforce a limit on
the version string length, an attacker could provide a long string that
would take up a large amount of resources, potentially taking a server
down. This issue therefore enables a potential Denial of Service attack.
This is a slightly differnt variant of a typical Regular Expression
Denial of Service
([ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS))
vulnerability.

Details {#details}
-------

\<\>

Remediation {#remediation}
-----------

Update to a version 4.3.2 or greater. From the issue description [2]:
"Package version can no longer be more than 256 characters long. This
prevents a situation in which parsing the version number can use
exponentially more time and memory to parse, leading to a potential
denial of service."

References {#references}
----------

-   [GitHub Release](https://github.com/npm/npm/releases/tag/v2.7.5)

Remediation {#remediation-1}
-----------

Upgrade `semver` to version 4.3.2 or higher.

References {#references-1}
----------

-   [GitHub Release](https://github.com/npm/npm/releases/tag/v2.7.5)

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/npm:semver:20150403)

Directory Traversal {.card__title}
-------------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: st
-   Introduced through: goof@1.0.1 and st@0.2.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › st@0.2.4

* * * * *

Overview {#overview}
--------

Versions prior to 0.2.5 did not properly prevent path traversal. Literal
dots in a path were resolved out, but url encoded dots were not. Thus, a
request like `/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd` would leak
sensitive files and data from the server.

As of version 0.2.5, any `'/../'` in the request path, urlencoded or
not, will be replaced with `'/'`. If your application depends on url
traversal, then you are encouraged to please refactor so that you do not
depend on having `..` in url paths, as this tends to expose data that
you may be surprised to be exposing.

Details {#details}
-------

A Directory Traversal attack (also known as path traversal) aims to
access files and directories that are stored outside the intended
folder. By manipulating files with "dot-dot-slash (../)" sequences and
its variations, or by using absolute file paths, it may be possible to
access arbitrary files and directories stored on file system, including
application source code, configuration, and other critical system files.

Directory Traversal vulnerabilities can be generally divided into two
types:

-   **Information Disclosure**: Allows the attacker to gain information
    about the folder structure or read the contents of sensitive files
    on the system.

`st` is a module for serving static files on web pages, and contains a
[vulnerability of this type](https://snyk.io/vuln/npm:st:20140206). In
our example, we will serve files from the `public` route.

If an attacker requests the following URL from our server, it will in
turn leak the sensitive private key of the root user.

    curl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa

**Note** `%2e` is the URL encoded version of `.` (dot).

-   **Writing arbitrary files**: Allows the attacker to create or
    replace existing files. This type of vulnerability is also known as
    `Zip-Slip`.

One way to achieve this is by using a malicious `zip` archive that holds
path traversal filenames. When each filename in the zip archive gets
concatenated to the target extraction folder, without validation, the
final path ends up outside of the target folder. If an executable or a
configuration file is overwritten with a file containing malicious code,
the problem can turn into an arbitrary code execution issue quite
easily.

The following is an example of a `zip` archive with one benign file and
one malicious file. Extracting the malicious file will result in
traversing out of the target folder, ending up in `/root/.ssh/`
overwriting the `authorized_keys` file:

    2018-04-15 22:04:29 .....           19           19  good.txt
              2018-04-15 22:04:42 .....           20           20  ../../../../../../root/.ssh/authorized_keys

Remediation {#remediation}
-----------

Upgrade to version 0.2.5 or greater.

References {#references}
----------

-   [https://github.com/isaacs/st\#security-status](https://github.com/isaacs/st#security-status)
-   [http://blog.npmjs.org/post/80277229932/newly-paranoid-maintainers](http://blog.npmjs.org/post/80277229932/newly-paranoid-maintainers)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:st:20140206)

Open Redirect {.card__title}
-------------

medium severity

* * * * *

-   Package Manager: npm
-   Vulnerable module: st
-   Introduced through: goof@1.0.1 and st@0.2.4

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1 › st@0.2.4

* * * * *

Overview {#overview}
--------

[`st`](https://www.npmjs.com/package/st) is a module for serving static
files.

Affected versions of this package are vulnerable to Open Redirect. A
malicious user could send a specially crafted request, which would
automatically redirect the request to another domain, controlled by the
attacker.

**Note:** `st` will only redirect if requests are served from the
root(`/`) and not from a subdirectory

References {#references}
----------

-   [GitHub
    Commit](https://github.com/isaacs/st/commit/579960c629f12a27428e2da84c54f517e37b0a16)

* * * * *

[More about this vulnerability](https://snyk.io/vuln/npm:st:20171013)

GPL-2.0 license {.card__title}
---------------

high severity

* * * * *

-   Package Manager: npm
-   Module: goof
-   Introduced through: [goof@1.0.1](/test//goof@1.0.1)

* * * * *

### Detailed paths {.card__section__title}

-   *Introduced through*: goof@1.0.1

* * * * *

GPL-2.0 license

* * * * *

[More about this
vulnerability](https://snyk.io/vuln/snyk:lic:npm:goof:GPL-2.0)

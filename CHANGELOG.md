# Changelog

## 0.1.0 (2026-11-05)


### Features

* add web app UI foundation with React, TypeScript, and TailwindCSS ([#69](https://github.com/codewithmuh/secure-file-transfer/issues/69)) ([b5b4293](https://github.com/codewithmuh/secure-file-transfer/commit/b5b429380ab6827a595942babd95506978044387))
* API service skeleton ([#65](https://github.com/codewithmuh/secure-file-transfer/issues/65)) ([050f9ad](https://github.com/codewithmuh/secure-file-transfer/commit/050f9ad189aa476f6c1ceb1822c4116584abbb0a))
* audit events with fail-closed writes ([#92](https://github.com/codewithmuh/secure-file-transfer/issues/92)) ([064303c](https://github.com/codewithmuh/secure-file-transfer/commit/064303ced30d5a23249ef9be6b58fd2162bf617e))
* data layer with Aurora, Valkey and SQS ([#101](https://github.com/codewithmuh/secure-file-transfer/issues/101)) ([#143](https://github.com/codewithmuh/secure-file-transfer/issues/143)) ([172e436](https://github.com/codewithmuh/secure-file-transfer/commit/172e4367bbf0a56ea7dbd56a6d19d51c537b610e))
* database foundation ([#75](https://github.com/codewithmuh/secure-file-transfer/issues/75)) ([f3af6e2](https://github.com/codewithmuh/secure-file-transfer/commit/f3af6e21f978e55cd076cc18ba223e653d393a49))
* DLP detector library and synthetic corpus ([#98](https://github.com/codewithmuh/secure-file-transfer/issues/98)) ([#142](https://github.com/codewithmuh/secure-file-transfer/issues/142)) ([7ab946a](https://github.com/codewithmuh/secure-file-transfer/commit/7ab946a334b8a8a6bbabee3e665f425de3855561))
* email templates in English and Japanese and the mail adapter ([#122](https://github.com/codewithmuh/secure-file-transfer/issues/122)) ([e478bed](https://github.com/codewithmuh/secure-file-transfer/commit/e478bedc7368021588c9ce816a26ae496f118816))
* generated TypeScript API client for the web app ([#116](https://github.com/codewithmuh/secure-file-transfer/issues/116)) ([7608161](https://github.com/codewithmuh/secure-file-transfer/commit/7608161dfd5e147b8f04342eb8528040b39f94b0))
* members, invitations, roles and the authorization matrix ([#112](https://github.com/codewithmuh/secure-file-transfer/issues/112)) ([#141](https://github.com/codewithmuh/secure-file-transfer/issues/141)) ([09f36a9](https://github.com/codewithmuh/secure-file-transfer/commit/09f36a9fe2f41e9e3d6b933ec177fe4e5388e735))
* OpenTelemetry traces in the service ([#121](https://github.com/codewithmuh/secure-file-transfer/issues/121)) ([35b3764](https://github.com/codewithmuh/secure-file-transfer/commit/35b376400a3f9ebf64dc1e3ffcf001f2cb298eb8))
* Problem error responses for every API error ([#117](https://github.com/codewithmuh/secure-file-transfer/issues/117)) ([a2352de](https://github.com/codewithmuh/secure-file-transfer/commit/a2352de43108b360036586aab52ffaa42f4b18dd))
* rate limiting with Valkey counters ([#120](https://github.com/codewithmuh/secure-file-transfer/issues/120)) ([5f8911a](https://github.com/codewithmuh/secure-file-transfer/commit/5f8911a82d3285153e4c83f2d248b2d10dc910b3))
* scoped data access and the tenant isolation suite ([#95](https://github.com/codewithmuh/secure-file-transfer/issues/95)) ([99bb7fc](https://github.com/codewithmuh/secure-file-transfer/commit/99bb7fc05542896a1a468dde086139ecd57ea137))
* transactional outbox and relay worker ([#115](https://github.com/codewithmuh/secure-file-transfer/issues/115)) ([5f3023f](https://github.com/codewithmuh/secure-file-transfer/commit/5f3023fe4ce75c261d93c42e08af06ec956f93af))


### Bug Fixes

* code-review findings on audit events ([#94](https://github.com/codewithmuh/secure-file-transfer/issues/94)) ([7d6e606](https://github.com/codewithmuh/secure-file-transfer/commit/7d6e606367bf7982d2075678fc3c0ec4425c4839))
* install Debian's security updates in the API image ([#126](https://github.com/codewithmuh/secure-file-transfer/issues/126)) ([#127](https://github.com/codewithmuh/secure-file-transfer/issues/127)) ([af691fd](https://github.com/codewithmuh/secure-file-transfer/commit/af691fd19ac48c8aa43f565b346d593315a159fe))
* regenerate the API client from the current contract ([#124](https://github.com/codewithmuh/secure-file-transfer/issues/124)) ([#125](https://github.com/codewithmuh/secure-file-transfer/issues/125)) ([41bec98](https://github.com/codewithmuh/secure-file-transfer/commit/41bec9884e67c4ba68c3436ebb13f5b88d611d28))
* restore the [#81](https://github.com/codewithmuh/secure-file-transfer/issues/81) doc changes that [#95](https://github.com/codewithmuh/secure-file-transfer/issues/95) reverted ([#123](https://github.com/codewithmuh/secure-file-transfer/issues/123)) ([82dc975](https://github.com/codewithmuh/secure-file-transfer/commit/82dc975168f6a9e49f810e05dfa09c05816a0390))
* run promotion-gate's script from the base commit ([#132](https://github.com/codewithmuh/secure-file-transfer/issues/132)) ([#133](https://github.com/codewithmuh/secure-file-transfer/issues/133)) ([c5746db](https://github.com/codewithmuh/secure-file-transfer/commit/c5746db8d37ec64d5bbd72f4193c7038db21e70e))
* sign-in flow defects in the web app ([#90](https://github.com/codewithmuh/secure-file-transfer/issues/90)) ([99fde8f](https://github.com/codewithmuh/secure-file-transfer/commit/99fde8f031454fa9c3065a4d82895ce9bb4c60bf))
* state bucket settings and backend checks ([#93](https://github.com/codewithmuh/secure-file-transfer/issues/93)) ([8b7cd6d](https://github.com/codewithmuh/secure-file-transfer/commit/8b7cd6d454202df72be4e67b04876d04d78bb8ad))

/**
 * The only additional /recon prompt material not covered by the web/infrastructure
 * playbooks: typed handling for explicitly scoped non-web assets.
 */

export const RECON_SPECIALIZED_ASSET_PROMPT = `SPECIALIZED NON-WEB ASSET HANDLING — USE ONLY WHEN PRESENT IN PERSISTED SCOPE

The canonical /recon workflow owns orchestration and completion. recon-master owns web and infrastructure technique chapters. This supplement covers only assets that do not fit the hostname/URL inventories.

- For explicitly in-scope mobile applications, APK/IPA files, source repositories, binaries, cloud resources, or other non-web objects, keep a typed asset record with its exact identifier, version or content hash, origin/source, scope decision, permitted test surface, and evidence location.
- Do not coerce package IDs, repository names, cloud resource IDs, or binary hashes into subdomain/URL rows. Keep them in the existing canonical asset/evidence model and link them to the appropriate platform-specific specialist procedure.
- A discovered repository, cloud identifier, app package, binary, IP, or related organization asset is not automatically authorized. Preserve ambiguous/out-of-scope leads without active probing.
- Do not create a separate non-web methodology, duplicated tool catalog, or report per asset. Merge each observation into the existing target inventory and final report with its provenance and disposition.`
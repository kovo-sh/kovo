// @kovo/adapters/osv: the real OsvFeedPort over OSV's public bucket and API (BUILD_PLAN item 11).
// Fake: @kovo/adapters/fakes/osv. Status: docs/status/adapter-feeds.md.

export {
  DEFAULT_OSV_FEED_LIMITS,
  OSV_API_ORIGIN,
  OsvHttpFeed,
  vulnerabilityUrl,
  type OsvFeedLimits,
  type OsvHttpFeedOptions,
} from "./adapter.js";
export { parseChangeListLine, readChangeList, type ChangeListRead } from "./change-list.js";
export {
  GCS_ORIGIN,
  OSV_BUCKET,
  OSV_CHANGE_LIST_OBJECT,
  OSV_EXPORT_OBJECT,
  objectMediaUrl,
  objectMetadataUrl,
} from "./gcs.js";
export { osvRecordFromDocument } from "./record.js";
export { readZipEntries, type ZipEntry, type ZipLimits } from "./zip.js";

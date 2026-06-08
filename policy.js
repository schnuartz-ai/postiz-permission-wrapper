'use strict';
const { getKeyChannelPolicy, logActivity } = require('./db');

/**
 * Extracts channel/integration IDs from the Postiz POST /posts body.
 */
function extractChannelIds(body) {
  const ids = new Set();

  if (Array.isArray(body.posts)) {
    for (const post of body.posts) {
      if (post?.integration?.id) ids.add(String(post.integration.id));
    }
  }

  if (body.integrationId)               ids.add(String(body.integrationId));
  if (Array.isArray(body.integrationIds)) body.integrationIds.forEach(id => ids.add(String(id)));
  if (body.channelId)                   ids.add(String(body.channelId));
  if (Array.isArray(body.channelIds))   body.channelIds.forEach(id => ids.add(String(id)));

  return [...ids];
}

/**
 * Applies per-key channel policies to a request body.
 * keyId: the API key ID making the request (required for per-key policies)
 *
 * Policies (per channel, default = 'draft'):
 *   auto    → pass request through unchanged
 *   draft   → rewrite type to 'draft' before forwarding
 *   blocked → reject with 403, do not forward
 */
function applyPolicy(body, requestPath, keyId) {
  const channelIds    = extractChannelIds(body);
  const requestedType = body.type || 'unknown';

  // ── No channels identifiable → safe default: force draft ─────────────────
  if (channelIds.length === 0) {
    if (requestedType === 'draft' || requestedType === 'unknown') {
      logActivity({ channelIds: [], requestedType, effectiveType: requestedType, policyApplied: 'passthrough', requestPath, keyId });
      return { body, modified: false, blocked: false };
    }
    const modifiedBody = { ...body, type: 'draft' };
    logActivity({ channelIds: [], requestedType, effectiveType: 'draft', policyApplied: 'no-channels-found', requestPath, keyId });
    return { body: modifiedBody, modified: true, blocked: false };
  }

  // ── Collect per-key per-channel policies ──────────────────────────────────
  const policies = channelIds.map(id => ({ id, policy: getKeyChannelPolicy(keyId, id) }));

  // Any channel blocked? → block entire request
  const anyBlocked = policies.some(p => p.policy === 'blocked');
  if (anyBlocked) {
    const blockedIds = policies.filter(p => p.policy === 'blocked').map(p => p.id);
    logActivity({ channelIds, requestedType, effectiveType: 'blocked', policyApplied: 'blocked', requestPath, keyId });
    return { body, modified: false, blocked: true, blockedChannels: blockedIds };
  }

  // If type is draft or unknown → pass through (no live-posting attempt)
  if (requestedType === 'draft' || requestedType === 'unknown') {
    logActivity({ channelIds, requestedType, effectiveType: requestedType, policyApplied: 'passthrough', requestPath, keyId });
    return { body, modified: false, blocked: false };
  }

  // type is 'now' or 'schedule' → all channels must be 'auto'
  const allAuto = policies.every(p => p.policy === 'auto');
  if (allAuto) {
    logActivity({ channelIds, requestedType, effectiveType: requestedType, policyApplied: 'auto', requestPath, keyId });
    return { body, modified: false, blocked: false };
  }

  // At least one channel is 'draft' → downgrade
  const modifiedBody = { ...body, type: 'draft' };
  logActivity({ channelIds, requestedType, effectiveType: 'draft', policyApplied: 'draft', requestPath, keyId });
  return { body: modifiedBody, modified: true, blocked: false };
}

module.exports = { applyPolicy, extractChannelIds };

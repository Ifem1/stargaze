import type { EvidenceSource } from './evidence-sources';

type ReleaseRecord = {
  id?: string; project?: string; repository_url?: string; owner?: string; version?: string;
  commit_sha?: string; artifact_digest?: string; ecosystem?: string; package_name?: string;
  manifest_digest?: string; predecessor_id?: string;
};

type AssessmentRecord = {
  id?: string; release_id?: string; advisory_id?: string; revision?: string; title?: string;
  ecosystem?: string; package_name?: string; policy_version?: string; registered_by?: string;
  sources?: Array<{ url: string; role: string }>;
};

export type AssessmentAttemptManifestEntry = { url?: string; role?: string; kind?: string; response_status?: number; body_sha256?: string; body_bytes?: number; metadata_identity_valid?: boolean; revision_authenticated?: boolean };
export type AssessmentAttemptRecord = { id?: string; assessment_id?: string; sequence?: number; state?: string; packet_digest?: string; failure_reason?: string; manifest?: AssessmentAttemptManifestEntry[] };

export function confirmReleaseRecord(record: ReleaseRecord, expected: {
  project: string; repository: string; owner: string; version: string; commit: string;
  artifact: string; ecosystem: string; package: string; manifest: string; predecessor: string;
}): string {
  if (!record.id || record.project !== expected.project || record.repository_url !== expected.repository
      || record.owner?.toLowerCase() !== expected.owner.toLowerCase() || record.version !== expected.version
      || record.commit_sha !== expected.commit || record.artifact_digest !== expected.artifact
      || record.ecosystem !== expected.ecosystem || record.package_name !== expected.package
      || record.manifest_digest !== expected.manifest || record.predecessor_id !== expected.predecessor) {
    throw new Error('Finalized release record does not exactly match the submitted identity.');
  }
  return record.id;
}

export function confirmAssessmentRecord(record: AssessmentRecord, expected: {
  releaseId: string; advisoryId: string; revision: string; title: string; ecosystem: string;
  package: string; policy: string; requester: string; sources: EvidenceSource[];
}): string {
  const committedSources = (record.sources ?? []).map(({ url, role }) => ({ url, role }));
  if (!record.id || record.release_id !== expected.releaseId || record.advisory_id !== expected.advisoryId
      || record.revision !== expected.revision || record.title !== expected.title
      || record.ecosystem !== expected.ecosystem || record.package_name !== expected.package
      || record.policy_version !== expected.policy
      || record.registered_by?.toLowerCase() !== expected.requester.toLowerCase()
      || JSON.stringify(committedSources) !== JSON.stringify(expected.sources)) {
    throw new Error('Finalized assessment record does not exactly match the submitted identity and evidence list.');
  }
  return record.id;
}

export function confirmAssessmentAttempt(record: AssessmentRecord & { attempt_count?: number; packet_digest?: string; state?: string },
  attempt: AssessmentAttemptRecord, expected: { assessmentId: string; sequence: number }): string {
  const attemptId = `${expected.assessmentId}/attempt-${expected.sequence}`;
  if (record.id !== expected.assessmentId || record.attempt_count !== expected.sequence
      || attempt.id !== attemptId || attempt.assessment_id !== expected.assessmentId
      || attempt.sequence !== expected.sequence || attempt.state !== record.state
      || !attempt.packet_digest || attempt.packet_digest !== record.packet_digest) {
    throw new Error('Finalized assessment attempt does not match the exact assessment and sequence.');
  }
  return attemptId;
}

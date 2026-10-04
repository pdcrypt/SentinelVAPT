import { downloadArtifact } from "@/lib/artifacts";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ reportId: string; fmt: string }> },
): Promise<Response> {
  const { reportId, fmt } = await params;
  return downloadArtifact("retest-reports", reportId, fmt);
}

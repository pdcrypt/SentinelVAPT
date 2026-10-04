import { previewArtifact } from "@/lib/artifacts";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ reportId: string }> },
): Promise<Response> {
  const { reportId } = await params;
  return previewArtifact("retest-reports", reportId);
}

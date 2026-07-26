import {
  invalidScanID,
  proxyControl,
  validScanID,
} from "../../../_proxy";

export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ id: string }>;
};

export async function GET(request: Request, context: RouteContext) {
  const { id } = await context.params;
  if (!validScanID(id)) return invalidScanID();
  return proxyControl(
    request,
    `/api/v1/scans/${encodeURIComponent(id)}/events`,
    { stream: true },
  );
}

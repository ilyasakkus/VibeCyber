import { proxyControl } from "../_proxy";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return proxyControl(request, "/api/v1/health");
}

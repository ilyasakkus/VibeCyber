import { proxyControl } from "../_proxy";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return proxyControl(request, "/api/v1/scans");
}

export function POST(request: Request) {
  return proxyControl(request, "/api/v1/scans");
}

export function DELETE(request: Request) {
  return proxyControl(request, "/api/v1/scans");
}

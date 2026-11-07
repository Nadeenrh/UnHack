import { NextResponse } from "next/server";

// Any /api path that no real route handles gets a JSON 404 (not Next's HTML page),
// whatever the method, so API clients and the replay tool get a readable error.
function notFound() {
  return NextResponse.json({ success: false, message: "This route does not exist.", code: "not_found" }, { status: 404 });
}

export { notFound as GET, notFound as POST, notFound as PUT, notFound as PATCH, notFound as DELETE };

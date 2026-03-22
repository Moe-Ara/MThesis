from __future__ import annotations

import uvicorn


if __name__ == "__main__":
    uvicorn.run("reasoning_siem.api.app:app", host="0.0.0.0", port=8008, reload=True)



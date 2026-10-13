from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from ....schemas import TakedownRequest, TakedownResponse
from ....takedown import generate_takedown_notice, build_takedown_pdf_bytes

router = APIRouter()


@router.post("/takedown", response_model=TakedownResponse)
@router.post("/report", response_model=TakedownResponse)
async def create_takedown_package(payload: TakedownRequest) -> TakedownResponse:
    return await run_in_threadpool(generate_takedown_notice, payload)


@router.post("/takedown/pdf")
@router.post("/report/pdf")
async def export_takedown_pdf(payload: TakedownRequest) -> Response:
    pdf_bytes = await run_in_threadpool(build_takedown_pdf_bytes, payload)
    filename = f"BrandShield_Takedown_{payload.scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

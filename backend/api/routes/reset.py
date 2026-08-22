"""
backend/api/routes/reset.py
============================
Provides an endpoint to completely wipe the active session data from the database.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from loguru import logger

from backend.api.dependencies import get_db

router = APIRouter(tags=["System Control"])

@router.post("/reset", summary="Wipe all session data")
async def reset_dashboard(session: AsyncSession = Depends(get_db)):
    """
    Scorched-earth database wipe for session management.
    Deletes all records from file_events, alerts, process_snapshots, and threat_scores.
    """
    logger.warning("Initiating full scorched-earth database wipe for active session.")
    try:
        # We use DELETE FROM instead of TRUNCATE to avoid permission issues, 
        # and execute them securely inside a single transaction.
        await session.execute(text("DELETE FROM alerts;"))
        await session.execute(text("DELETE FROM file_events;"))
        await session.execute(text("DELETE FROM process_snapshots;"))
        await session.execute(text("DELETE FROM threat_scores;"))
        
        await session.commit()
        
        logger.success("Database wipe completed successfully.")
        return {"status": "success", "message": "All session data purged."}
    
    except Exception as e:
        await session.rollback()
        logger.error(f"Database wipe failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to wipe database: {e}"
        )

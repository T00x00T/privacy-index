from __future__ import annotations

                                                  
                            
                                                  
                                     
 
                                                                           
                                                                          
import sys
from pathlib import Path

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root))

from privacy_index.main import main

raise SystemExit(main())

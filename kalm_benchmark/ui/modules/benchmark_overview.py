import altair as alt
import pandas as pd
import streamlit as st
from loguru import logger

def show():
    """Display the main CCSS overview page with scanner alignment analysis.

    :return: None
    """

    # CCSS Overview Header with rich Dynatrace gradient palette
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0;
                    background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 20%,\
                      #74b9ff 40%, #00cec9 60%, #55efc4 80%, #6c5ce7 100%);
                    border-radius: 20px; margin-bottom: 2rem;
                    box-shadow: 0 15px 40px rgba(108, 92, 231, 0.5);
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 15% 25%, rgba(162, 155, 254, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 85% 75%, rgba(116, 185, 255, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 50% 15%, rgba(0, 206, 201, 0.3) 0%, transparent 45%),
                                    radial-gradient(circle at 25% 85%, rgba(85, 239, 196, 0.3) 0%, transparent 45%);
                        pointer-events: none;"></div>
            <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800;
                           text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                    🛡️ Benchmark Overview
                </h1>
                <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem;
                          font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                    An overview of benchmarks used in Kalm Benchmark
                </h3>
                <p style="color: rgba(255,255,255,0.9); max-width: 650px; margin: 0 auto;
                         line-height: 1.7; font-size: 1.15rem; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">
                    Get an overview how different benchmarks are mapped to the Kalm Benchmark.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if __name__ == "__main__":
    show()

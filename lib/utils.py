from pandas.api.types import is_period_dtype

def normalize_periods(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    period_cols = [c for c in out.columns if is_period_dtype(out[c])]
    for c in period_cols:
        # choose one:
        # 1) to timestamps (good if periods represent time)
        out[c] = out[c].dt.to_timestamp()
        # 2) or to string: out[c] = out[c].astype("string")
    return out
def generate_auto_reply(is_scam: bool) -> str:
    if is_scam:
        return (
            "Thank you for your job offer. However, after further review, "
            "I have concerns that this may be a scam. Please be advised to "
            "exercise caution when sharing personal information or making any payments. "
            "I will not be pursuing this opportunity."
        )
    else:
        return "Thank you for the job offer. I am interested in pursuing this opportunity."
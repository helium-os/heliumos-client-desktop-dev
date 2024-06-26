import { createStyles } from 'antd-style';

const useStyles = createStyles(({ token, css, prefixCls }) => {
    return {
        installGuideContainer: css`
            & > h2 {
                color: rgba(255, 255, 255, 0.8);
                text-align: center;
                text-shadow: 0 2px 3px rgba(48, 48, 48, 0.06);
                font-size: 32px;
                line-height: 45px;
                font-weight: 500;
            }
            & > p {
                margin-top: 2px;
                color: rgba(255, 255, 255, 0.8);
                text-align: center;
                text-shadow: 0 2px 3px rgba(48, 48, 48, 0.06);
                font-size: 15px;
                font-weight: 400;
                opacity: 0.9;
            }
            .ant-btn {
                margin-top: 28px;
            }
        `,
        avatarBox: css`
            position: relative;
            width: 120px;
            height: 120px;
            margin-bottom: 16px;
            border-radius: 50%;
            box-shadow: 0 4px 4px 0 rgba(0, 0, 0, 0.25);
            backdrop-filter: blur(0.5px);
        `,
        avatar: css`
            position: absolute;
            top: 5px;
            left: 5px;
            right: 5px;
            bottom: 5px;
        `,
        installBtn: css`
            padding: 5px 16px;
            height: 30px;
            background: linear-gradient(0deg, rgba(0, 0, 0, 0.06) 0%, rgba(0, 0, 0, 0.06) 100%), #fff !important;
            line-height: 1;
            border: none !important;
            &:hover {
                color: rgba(0, 0, 0, 0.9) !important;
            }
        `,
    };
});

export default useStyles;

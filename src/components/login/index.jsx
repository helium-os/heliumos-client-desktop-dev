import { useState, useEffect } from 'react';
import { Form } from 'antd';
import BgLayout from '@/components/structure/BgLayout';
import SwitchModeType from '@/components/structure/SwitchModeType';
import { ModeType } from '@/utils/data';
import LoginByAlias from './LoginByAlias';
import LoginByIp from './LoginByIp';
import useStyles from './style';

const loginTypeMap = {
    alias: 'alias',
    ip: 'ip',
};

export default function Page({ loginType }) {
    const { styles } = useStyles();

    const [form] = Form.useForm();

    const [back, setBack] = useState(true);

    const addObverser = async () => {
        if (window?.versions) {
            await window?.versions?.getMessage('change-env', (event, arg) => {
                form.setFieldsValue({ usePoint: '' });
                setBack(false);
            });
            let name = await window?.versions?.invokMethod('getUserValue', 'name');
            setBack(!!name);
        }
    };
    useEffect(() => {
        addObverser();
    }, []);

    const getLoginForm = () => {
        switch (loginType) {
            case loginTypeMap.alias:
                return <LoginByAlias />;
            case loginTypeMap.ip:
                return <LoginByIp />;
        }
    };

    return (
        <>
            <BgLayout className={styles.loginPageContainer}>
                {getLoginForm()}
                {window.history.length > 1 && back && (
                    <div
                        className="goBack"
                        onClick={() => {
                            console.log(window.history.length);
                            window.history.back();
                        }}
                    >
                        返回
                    </div>
                )}
            </BgLayout>
            <SwitchModeType defaultModeType={ModeType.Normal} />
        </>
    );
}

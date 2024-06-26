import React, { useState, useEffect, useMemo, useCallback, memo } from 'react';
import useStyles from './style';
import PathSetting from './PathSetting';
import { BaseTabContentProps, Step } from '@/components/install-process/data';
import PanelLayout from '../common/PanelLayout';
import FooterButtons from '../common/FooterButtons';
import { getGuideLinkPrefix } from '@/utils/utils';

export interface IProps extends BaseTabContentProps {}

export type BaseEnvItem = {
    id: string;
    name: string;
    installLink: string;
};

type WholeEnvItem = {
    version?: string;
    pass?: boolean;
} & BaseEnvItem;

const baseEnvList: BaseEnvItem[] = [
    {
        id: 'kubectl',
        name: 'Kubectl',
        installLink: `${getGuideLinkPrefix() + '/install_kubectl'}`,
    },
    {
        id: 'helm',
        name: 'Helm',
        installLink: `${getGuideLinkPrefix() + '/install_helm'}`,
    },
];

const EnvCheck: React.FC<IProps> = ({ onStep, ...restProps }) => {
    const { styles } = useStyles();
    const [envList, setEnvList] = useState<WholeEnvItem[]>([...baseEnvList]);

    const disabled = useMemo(() => envList.some((item) => !item.pass), [envList]);

    const onVersionAndPassChange = useCallback(
        (id: string, version: string, pass: boolean) => {
            const newEnvList = [...envList];
            const index = newEnvList.findIndex((item) => item.id === id);

            if (index !== -1) {
                newEnvList.splice(index, 1, {
                    ...newEnvList[index],
                    version,
                    pass,
                });
            }
            setEnvList(newEnvList);
        },
        [envList],
    );

    const footerButtons = useMemo(
        () => (
            <FooterButtons
                primaryButton={{
                    text: '下一步',
                    disabled,
                    onClick: () => onStep?.(Step.Next),
                }}
            />
        ),
        [disabled, onStep],
    );

    return (
        <PanelLayout footer={footerButtons} {...restProps}>
            <ul className={styles.envList}>
                {envList.map((item) => (
                    <li key={item.id}>
                        <PathSetting {...item} onVersionAndPassChange={onVersionAndPassChange} />
                    </li>
                ))}
            </ul>
        </PanelLayout>
    );
};

export default memo(EnvCheck);

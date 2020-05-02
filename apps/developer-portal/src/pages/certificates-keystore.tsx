/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { hasRequiredScopes } from "@wso2is/core/helpers";
import { EmptyPlaceholder, LinkButton, PrimaryButton } from "@wso2is/react-components";
import React, { FunctionComponent, ReactElement, useContext, useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { DropdownProps, Icon, PaginationProps } from "semantic-ui-react";
import { listCertificateAliases } from "../api";
import { CertificatesList, ImportCertificate } from "../components";
import { EmptyPlaceholderIllustrations } from "../configs";
import { UserConstants } from "../constants";
import { ListLayout, PageLayout } from "../layouts";
import { AlertLevels, Certificate, FeatureConfigInterface } from "../models";
import { AppState } from "../store";
import { filterList, sortList, hasScope } from "../utils";
import { useTranslation } from "react-i18next";
import { addAlert } from "@wso2is/core/dist/src/store";
import { AdvancedSearchWithBasicFilters } from "../components/shared/advanced-search-with-basic-filters";

/**
 * This renders the Userstores page.
 *
 * @return {ReactElement}
 */
export const CertificatesKeystore: FunctionComponent<{}> = (): ReactElement => {

    /**
     * Sets the attributes by which the list can be sorted.
     */
    const SORT_BY = [
        {
            key: 0,
            text: "Alias",
            value: "alias"
        }
    ];

    const [ certificatesKeystore, setCertificatesKeystore ] = useState<Certificate[]>([]);
    const [ offset, setOffset ] = useState(0);
    const [ listItemLimit, setListItemLimit ] = useState<number>(0);
    const [ openModal, setOpenModal ] = useState(false);
    const [ isLoading, setIsLoading ] = useState(true);
    const [ filteredCertificatesKeystore, setFilteredCertificatesKeystore ] = useState<Certificate[]>([]);
    const [ sortBy, setSortBy ] = useState(SORT_BY[ 0 ]);
    const [ sortOrder, setSortOrder ] = useState(true);
    const [ isSuper, setIsSuper ] = useState(true);
    const [ query, setQuery ] = useState("");

    const tenantDomain: string = useSelector<AppState, string>((state: AppState) => state.config.deployment.tenant);
    const featureConfig: FeatureConfigInterface = useSelector((state: AppState) => state.config.features);

    const dispatch = useDispatch();

    const { t } = useTranslation();

    useEffect(() => {
        if (tenantDomain === "carbon.super") {
            setIsSuper(true);
        } else {
            setIsSuper(false);
        }
    }, [ tenantDomain ]);

    /**
     * Fetches all certificates.
     *
     * @param {number} limit.
     * @param {string} sort.
     * @param {number} offset.
     * @param {string} filter.
     */
    const fetchCertificatesKeystore = () => {
        setIsLoading(true);
        listCertificateAliases().then(response => {
            setCertificatesKeystore(response);
            setFilteredCertificatesKeystore(response);
            setIsLoading(false);
        }).catch(error => {
            setIsLoading(false);
            dispatch(addAlert(
                {
                    description: error?.description || "An error occurred while fetching certificates",
                    level: AlertLevels.ERROR,
                    message: error?.message || "Something went wrong"
                }
            ));
        });
    };

    useEffect(() => {
        setListItemLimit(UserConstants.DEFAULT_USER_LIST_ITEM_LIMIT);
        fetchCertificatesKeystore();
    }, []);

    useEffect(() => {
        setFilteredCertificatesKeystore((sortList(filteredCertificatesKeystore, sortBy.value, sortOrder)));
    }, [ sortBy, sortOrder ]);

    /**
     * This slices and returns a portion of the list.
     *
     * @param {number} list.
     * @param {number} limit.
     * @param {number} offset.
     *
     * @return {Certificate[]} Paginated list.
     */
    const paginate = (list: Certificate[], limit: number, offset: number): Certificate[] => {
        return list?.slice(offset, offset + limit);
    };

    /**
     * Handles the change in the number of items to display.
     *
     * @param {React.MouseEvent<HTMLAnchorElement>} event.
     * @param {DropdownProps} data.
     */
    const handleItemsPerPageDropdownChange = (event: React.MouseEvent<HTMLAnchorElement>, data: DropdownProps) => {
        setListItemLimit(data.value as number);
    };

    /**
     * This paginates.
     *
     * @param {React.MouseEvent<HTMLAnchorElement>} event.
     * @param {PaginationProps} data.
     */
    const handlePaginationChange = (event: React.MouseEvent<HTMLAnchorElement>, data: PaginationProps) => {
        setOffset((data.activePage as number - 1) * listItemLimit);
    };

    /**
     * Handles sort order change.
     *
     * @param {boolean} isAscending.
     */
    const handleSortOrderChange = (isAscending: boolean) => {
        setSortOrder(isAscending);
    };

    /**
     * Handle sort strategy change.
     *
     * @param {React.SyntheticEvent<HTMLElement>} event.
     * @param {DropdownProps} data.
     */
    const handleSortStrategyChange = (event: React.SyntheticEvent<HTMLElement>, data: DropdownProps) => {
        setSortBy(SORT_BY.filter(option => option.value === data.value)[ 0 ]);
    };

    /**
     * Handles the `onFilter` callback action from the search component.
     *
     * @param {string} query - Search query.
     */
    const handleKeystoreFilter = (query: string): void => {
        // TODO: Implement once the API is ready
        // fetchCertificatesKeystore(null, null, null, query);
        setFilteredCertificatesKeystore(
            filterList(certificatesKeystore, query, "alias", true)
        );
    };

    return (
        <>
            {
                openModal
                && (
                    <ImportCertificate
                        open={ openModal }
                        onClose={ () => setOpenModal(false) }
                        update={ fetchCertificatesKeystore }
                    />
                )
            }
            <PageLayout
                title="Certificates"
                description="Create and manage certificates in the keystore"
                showBottomDivider={ true }
            >
                {
                    filteredCertificatesKeystore?.length > 0
                        ? (<ListLayout
                            advancedSearch={
                                <AdvancedSearchWithBasicFilters
                                    onFilter={ handleKeystoreFilter }
                                    filterAttributeOptions={ [
                                        {
                                            key: 0,
                                            text: "Alias",
                                            value: "alias"
                                        }
                                    ] }
                                    filterAttributePlaceholder={
                                        t("devPortal:components.certificates.keystore.advancedSearch.form.inputs" +
                                            ".filterAttribute.placeholder")
                                    }
                                    filterConditionsPlaceholder={
                                        t("devPortal:components.certificates.keystore.advancedSearch.form.inputs" +
                                            ".filterCondition.placeholder")
                                    }
                                    filterValuePlaceholder={
                                        t("devPortal:components.certificates.keystore.advancedSearch.form.inputs" +
                                            ".filterValue.placeholder")
                                    }
                                    placeholder={
                                        t("devPortal:components.certificates.keystore.advancedSearch.placeholder")
                                    }
                                    defaultSearchAttribute="alias"
                                    defaultSearchOperator="co"
                                />
                            }
                            currentListSize={ listItemLimit }
                            listItemLimit={ listItemLimit }
                            onItemsPerPageDropdownChange={ handleItemsPerPageDropdownChange }
                            onPageChange={ handlePaginationChange }
                            onSortStrategyChange={ handleSortStrategyChange }
                            onSortOrderChange={ handleSortOrderChange }
                            rightActionPanel={
                                (hasRequiredScopes(featureConfig?.certificates,
                                    featureConfig?.certificates?.scopes?.create)
                                    && !isSuper) && (
                                    <PrimaryButton
                                        onClick={ () => {
                                            setOpenModal(true);
                                        } }
                                    >
                                        <Icon name="cloud upload" />Import Certificate
                                    </PrimaryButton>
                                )
                            }
                            leftActionPanel={ null }
                            showPagination={ true }
                            sortOptions={ SORT_BY }
                            sortStrategy={ sortBy }
                            totalPages={ Math.ceil(filteredCertificatesKeystore?.length / listItemLimit) }
                            totalListSize={ filteredCertificatesKeystore?.length }
                        >
                            <CertificatesList
                                list={ paginate(filteredCertificatesKeystore, listItemLimit, offset) }
                                update={ fetchCertificatesKeystore }
                                type="keystore"
                                featureConfig={ featureConfig }
                            />
                        </ListLayout>
                        )
                        : !isLoading &&
                            (!certificatesKeystore
                                || (certificatesKeystore.length === 0 && filteredCertificatesKeystore.length === 0))
                            ? (
                                <EmptyPlaceholder
                                    action={
                                        (hasRequiredScopes(featureConfig?.certificates,
                                            featureConfig?.certificates?.scopes?.create)
                                            && !isSuper) && (
                                            <PrimaryButton
                                                onClick={ () => {
                                                    setOpenModal(true);
                                                } }
                                            >
                                                <Icon name="upload" /> Import Certificate
                                            </PrimaryButton>
                                        )
                                    }
                                    title="Import Certificate"
                                    subtitle={ [ "Currently, there are no certificates available." ] }
                                    image={ EmptyPlaceholderIllustrations.emptyList }
                                    imageSize="tiny"
                                />
                            )
                            : !isLoading && (
                                <EmptyPlaceholder
                                    action={ (
                                        <LinkButton onClick={ () => {
                                            setFilteredCertificatesKeystore(certificatesKeystore);
                                        } }
                                        >
                                            Clear search query
                                        </LinkButton>
                                    ) }
                                    image={ EmptyPlaceholderIllustrations.emptySearch }
                                    imageSize="tiny"
                                    title={ "No results found" }
                                    subtitle={ [
                                        `We couldn't find any results for "${query}"`,
                                        "Please try a different search term."
                                    ] }
                                />
                            )
                }
            </PageLayout>
        </>
    );
};